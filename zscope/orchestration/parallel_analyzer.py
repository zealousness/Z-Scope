"""
Parallel Analyzer for Z-SCOPE.
Supports concurrent analysis of multiple functions using thread pool.
"""

import concurrent.futures
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from copy import copy, deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field, replace

from ..config.config import ZScopeConfig, minimum_optional_positive_seconds
from ..config.function_entry import FunctionEntry
from ..config.user_config_store import UserConfigStore
from ..core.candidates.evidence import SemanticOverlayCompiler
from ..core.candidates.decision_facts import DecisionFactGraphCache
from ..core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from ..core.analysis.analyzer import Analyzer
from ..core.validation.runner import ValidationResultCache
from ..framework.llm_client import LLMClient
from ..semantics.inference import LocalPatternSemanticBuilder
from ..semantics.models import LocalPatternSemantics
from ..snapshots.store import SnapshotStore
from ..retrieval.code_index import CodeIndex
from ..orchestration.candidates import CandidateLedger
from ..orchestration.candidate_envelope import annotate_issue_identity
from ..orchestration.global_modeler import GlobalModeler
from ..orchestration.scheduler import ENTRY_ROLE, ScanScheduler
from ..common.issue_identity import (
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
    deduplicate_issues,
    flatten_issue_text,
    issue_call_path_signature,
    issue_resource_signature,
    issue_rank,
    issue_sink_signature,
    issues_may_share_root_cause,
    merge_duplicate_issue,
    normalize_issue_category,
    normalize_issue_key_part,
    parse_issue_location,
    semantic_category_family,
    semantic_related_cluster_keys,
    semantic_root_cause_key,
)
from ..common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
)
from ..reporting.views import (
    build_report_views,
    coalesce_review_observations,
    report_view_summary,
)
from ..reporting.schema import apply_report_schema_v2, coalesce_terminal_candidates
from ..reporting.assembler import ReportAssembler

logger = logging.getLogger(__name__)

_ENTRY_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_ENTRY_CONTROL_RE = re.compile(r"\b(if|for|while|switch|case|goto)\b")
_ENTRY_HEAVY_TEXT_RE = re.compile(
    r"(pthread|thread|callback|worker|recv|send|read|write|open|fopen|mmap|"
    r"malloc|calloc|realloc|free|lock|unlock|shared|global|argv|getenv|protocol|"
    r"message|runtime|dispatch|session)",
    re.IGNORECASE,
)
_ENTRY_EXPOSURE_WEIGHTS = {
    "other_user_input": 420,
    "communication": 380,
    "thread": 360,
    "api": 140,
}


@dataclass
class ParallelAnalysisResult:
    """Result of parallel analysis across multiple functions."""
    function_name: str
    verdict: str
    entry_identity: str = ""
    entry_file_path: str = ""
    entry_signature: str = ""
    issues: List[Dict[str, Any]] = field(default_factory=list)
    audit_observations: List[Dict[str, Any]] = field(default_factory=list)
    candidate_terminal_states: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    entry_budget_seconds: Optional[float] = None
    entry_budget_exceeded: bool = False
    entry_budget_overrun_seconds: float = 0.0
    budget_exhaustion_policy: str = "observe"
    context_tokens: int = 0
    cumulative_prompt_tokens: int = 0
    cumulative_completion_tokens: int = 0
    cumulative_total_tokens: int = 0
    diff_focus: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ParallelAnalyzer:
    """
    Parallel analyzer that can analyze multiple functions concurrently.
    
    Uses a thread pool to run up to max_workers LLM analysis sessions
    simultaneously, significantly reducing total analysis time.
    """
    
    def __init__(self, config: ZScopeConfig, code_index: Optional[CodeIndex] = None,
                 user_config: Optional[UserConfigStore] = None,
                 force_ignore_history: bool = False,
                 maintain_mode: bool = False,
                 cancellation_token: Optional[CancellationToken] = None):
        self.base_config = config
        self.max_workers = max(
            1,
            int(
                getattr(config.analysis, "entry_workers", 0)
                or config.analysis.parallel_workers
                or 1
            ),
        )
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        self._shared_llm_clients = self._build_shared_llm_clients(config)
        self._validation_result_cache = ValidationResultCache(
            max_entries=getattr(config.analysis, "validation_cache_entries", 4096)
        )
        self._decision_fact_cache = DecisionFactGraphCache()
        self._candidate_ledger = CandidateLedger(
            project_id=str(
                getattr(config.project, "project_id", "")
                or config.project.project_root.name
            ),
            project_root=str(config.project.project_root),
            revision=Analyzer._git_commit_sha(config.project.project_root),
        )
        self._scheduler: Optional[ScanScheduler] = None

        if code_index:
            self.code_index = code_index
        else:
            self.code_index = CodeIndex(
                config.project.project_root,
                config.project.compile_commands_path,
                source_root=config.project.source_root,
                indexing_config=config.indexing,
                include_paths=config.project.include_paths,
                exclude_paths=config.project.exclude_paths,
                svf_parallel_workers=config.analysis.parallel_workers,
            )
        self.snapshot_store = SnapshotStore(Path(config.analysis.snapshot_dir))
        db_dir = Path(config.analysis.user_config_db) if config.analysis.user_config_db else Path(config.analysis.snapshot_dir)
        self.user_config = user_config or UserConfigStore(db_dir)
        self._interrupted = False
        self._deadline_exceeded = False
        self._parent_cancellation_token = cancellation_token
        self._cancellation_token = CancellationToken(parent=cancellation_token)
        self._shared_local_pattern_semantics: Optional[LocalPatternSemantics] = None
        self._shared_semantic_overlay: Optional[Dict[str, Any]] = None
        self._shared_semantics_lock = threading.Lock()
        # Candidate IR writes use the shared CodeIndex KnowledgeDB.  Serialize
        # the multi-statement write + commit transaction across entry workers.
        self._candidate_ir_persistence_lock = threading.Lock()
        self._last_batch_wall_seconds = 0.0
        self._last_scan_budget_metadata: Dict[str, Any] = {}
        self._last_global_model_stats: Optional[Dict[str, Any]] = None
        self._global_modeling_succeeded = False
        self._global_validation_state: Dict[str, Any] = {}
        self._global_validation_duration_seconds = 0.0
        self._project_fact_pass_state: Dict[str, Any] = {}
        self._semantic_dedup_llm_cache: Dict[str, Dict[str, Any]] = {}
        self.deferred_entry_candidates: List[Dict[str, Any]] = []
        self.run_id = uuid.uuid4().hex

    @staticmethod
    def _normalize_md_text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value)
        return text.replace("\\n", "\n")
        
    def analyze_function_entries(
        self,
        entries: List[FunctionEntry],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> Dict[str, ParallelAnalysisResult]:
        """
        Analyze multiple function entries with custom prompts.
        
        Args:
            entries: List of FunctionEntry objects with function names and custom prompts
            progress_callback: Optional callback(completed, total, func_name) for progress
            
        Returns:
            Dict mapping function name to analysis result
        """
        entries = self._materialize_entry_identities(entries)
        results = {}
        total = len(entries)
        completed = 0
        batch_started = time.monotonic()
        scan_budget_seconds = getattr(
            self.base_config.analysis,
            "scan_deadline_seconds",
            None,
        )
        budget_exhaustion_policy = "observe"
        self._interrupted = False
        self._deadline_exceeded = False
        self._cancellation_token = CancellationToken(
            parent=self._parent_cancellation_token,
            timeout_seconds=None,
        )
        self._candidate_ledger = CandidateLedger(
            project_id=str(
                getattr(self.base_config.project, "project_id", "")
                or self.base_config.project.project_root.name
            ),
            project_root=str(self.base_config.project.project_root),
            revision=Analyzer._git_commit_sha(
                self.base_config.project.project_root
            ),
        )
        self._decision_fact_cache = DecisionFactGraphCache()
        self._global_validation_state = {}
        self._global_validation_duration_seconds = 0.0
        self._project_fact_pass_state = {}
        self._cancellation_token.raise_if_cancelled()
        scheduler = ScanScheduler(
            entry_workers=self.max_workers,
            validator_workers=(
                getattr(self.base_config.analysis, "validator_workers", 0) or 4
            ),
            investigator_workers=(
                getattr(self.base_config.analysis, "investigator_workers", 0) or 2
            ),
        )
        self._scheduler = scheduler

        logger.info(f"Starting parallel analysis of {total} function entries with {self.max_workers} workers")
        try:
            if total and not self.maintain_mode:
                semantics_started = time.time()
                logger.info("[entry-worker] shared-semantics start entries=%d", total)
                self._prepare_shared_semantics()
                logger.info(
                    "[entry-worker] shared-semantics end entries=%d duration=%.2fs",
                    total,
                    time.time() - semantics_started,
                )
                if self.base_config.analysis.enable_global_model:
                    self._global_modeling_succeeded = self._run_global_modeling(entries)
                    if not self._global_modeling_succeeded:
                        raise RuntimeError(
                            "Global semantic modeling did not complete; entry analysis was not started."
                        )
                if bool(
                    getattr(
                        self.base_config.analysis,
                        "project_deterministic_fact_pass_v1",
                        False,
                    )
                ):
                    self._run_project_deterministic_fact_pass(entries)
        except Exception:
            scheduler.shutdown(wait=True, cancel_futures=True)
            self._scheduler = None
            raise

        scheduled_entries = self._prioritize_entries_for_execution(entries)
        try:
            # Submit all analysis tasks
            future_to_entry = {
                scheduler.submit(
                    ENTRY_ROLE,
                    self._analyze_single_entry,
                    entry,
                    priority=self._entry_scheduling_score(entry),
                ): entry
                for entry in scheduled_entries
            }
            
            # Collect results as they complete
            try:
                for future in concurrent.futures.as_completed(
                    future_to_entry,
                    timeout=self._cancellation_token.remaining_seconds(),
                ):
                    entry = future_to_entry[future]
                    completed += 1
                    
                    try:
                        result = future.result()
                        results[self._entry_result_key(entry)] = result
                        logger.info(f"[{completed}/{total}] {entry.function_name}: {result.verdict} ({len(result.issues)} issues, ctx ≈ {result.context_tokens:,} tokens)")
                    except concurrent.futures.CancelledError:
                        logger.warning(f"[{completed}/{total}] {entry.function_name}: Cancelled due to interrupt")
                    except Exception as e:
                        logger.error(f"[{completed}/{total}] {entry.function_name}: ERROR - {e}")
                        results[self._entry_result_key(entry)] = ParallelAnalysisResult(
                            function_name=entry.function_name,
                            verdict="error",
                            error=str(e),
                            diff_focus=entry.diff_focus,
                        )
                    
                    if progress_callback:
                        progress_callback(completed, total, entry.function_name)
            
            except KeyboardInterrupt:
                self._interrupted = True
                self._cancellation_token.cancel("scan_interrupted")
                logger.warning(
                    "\n[!] Scan interrupted by user (Ctrl+C). Cancelling queued work "
                    "and returning completed results. Running Python worker threads "
                    "cannot be force-killed safely."
                )
                
                # cancel_futures only affects queued work; already-running threads may
                # continue until the CLI takes the interrupted fast-exit path.
                scheduler.shutdown(wait=False, cancel_futures=True)
                
                logger.info(f"Returning {len(results)} completed results out of {total} total.")
                return results
            except concurrent.futures.TimeoutError:
                self._deadline_exceeded = True
                self._cancellation_token.cancel("scan_deadline_exceeded")
                logger.error(
                    "Scan deadline exceeded after %.2fs; cancelling queued entry work.",
                    time.monotonic() - batch_started,
                )
                for future, entry in future_to_entry.items():
                    entry_key = self._entry_result_key(entry)
                    if entry_key in results or future.done():
                        continue
                    future.cancel()
                    results[entry_key] = ParallelAnalysisResult(
                        function_name=entry.function_name,
                        verdict="error",
                        error="scan_deadline_exceeded",
                        diff_focus=entry.diff_focus,
                        metadata={"cancellation_reason": "scan_deadline_exceeded"},
                    )
                scheduler.shutdown(wait=False, cancel_futures=True)
                return results

            if self._uses_scan_validation_queue():
                self._run_scan_validation_queue()

        finally:
            self._last_batch_wall_seconds = time.monotonic() - batch_started
            self._last_scan_budget_metadata = self._scan_budget_metadata(
                duration_seconds=self._last_batch_wall_seconds,
                budget_seconds=scan_budget_seconds,
                policy=budget_exhaustion_policy,
            )
            if self._last_scan_budget_metadata["scan_budget_exceeded"]:
                logger.warning(
                    "Scan budget exceeded: budget=%.2fs overrun=%.2fs "
                    "policy=%s outcome=%s",
                    float(scan_budget_seconds),
                    self._last_scan_budget_metadata[
                        "scan_budget_overrun_seconds"
                    ],
                    budget_exhaustion_policy,
                    (
                        "completed"
                    ),
                )
            # Under normal successful execution, properly wait and clean up resources
            if scheduler and not (
                getattr(self, "_interrupted", False)
                or getattr(self, "_deadline_exceeded", False)
            ):
                try:
                    scheduler.shutdown(wait=True)
                except Exception:
                    pass
                    
        return results

    def _uses_scan_validation_queue(self) -> bool:
        # A few embedding and compatibility callers construct this facade with
        # ``object.__new__`` to exercise report projection only.  Those paths
        # have no configuration or batch lifecycle, so retain the pre-v3
        # per-entry behavior instead of assuming scan-level validation.
        analysis = getattr(getattr(self, "base_config", None), "analysis", None)
        return bool(
            getattr(analysis, "candidate_lifecycle_v3", True)
            and getattr(analysis, "global_validation_group_queue", True)
        )

    def _run_scan_validation_queue(self) -> None:
        """Validate each frozen v3 obligation once after all entries discover it.

        Entry workers can discover the same local sink through many wrappers.
        The shared ledger has already merged those occurrences by
        ``validation_cluster_uid``.  Validating inside each entry therefore
        spends LLM calls before that merge can have any effect.  This method
        restores the intended lifecycle: discovery -> ledger -> one global
        validation queue -> final report projection.
        """

        pending: List[Dict[str, Any]] = []
        for record in self._candidate_ledger.records():
            if (
                record.record_role != "validation_obligation"
                or record.disposition
            ):
                continue
            evidence = deepcopy(
                record.ticket.evidence
                if isinstance(record.ticket.evidence, dict)
                else {}
            )
            issue = deepcopy(evidence.pop("candidate_payload", {}) or {})
            if not issue:
                # Candidate payloads are persisted with every v3 obligation.
                # Retain a minimally reportable diagnostic rather than
                # silently dropping a malformed legacy producer.
                issue = {
                    "id": record.ticket.id,
                    "category": record.defect_class,
                    "defect_class": record.defect_class,
                    "description": record.ticket.task,
                    "source": record.ticket.origin,
                    "sink": record.ticket.sink,
                }
            issue["evidence_pack"] = evidence
            issue.setdefault("code_snippet", record.ticket.context_slice)
            issue.update(
                {
                    "candidate_schema_version": record.schema_version,
                    "candidate_uid": record.candidate_uid,
                    "history_key": record.history_key,
                    "obligation_uid": record.obligation_uid,
                    "decision_context_version": record.decision_context_version,
                    "evidence_hash": record.evidence_hash,
                    "decision_evidence_hash": record.decision_evidence_hash,
                    "validation_cluster_uid": record.validation_cluster_uid,
                    "context_signature": record.context_signature,
                    "occurrence_uid": (
                        record.occurrence_uids[0]
                        if record.occurrence_uids
                        else ""
                    ),
                    "occurrence_uids": list(record.occurrence_uids),
                    "call_paths": [list(path) for path in record.call_paths],
                    "entry_paths": [list(path) for path in record.call_paths],
                    "entry_identity": (
                        record.occurrences[0].entry_identity
                        if record.occurrences
                        else str(issue.get("entry_identity") or "")
                    ),
                }
            )
            evidence.update(
                {
                    "candidate_uid": record.candidate_uid,
                    "evidence_hash": record.evidence_hash,
                    "decision_evidence_hash": record.decision_evidence_hash,
                    "validation_cluster_uid": record.validation_cluster_uid,
                    "context_signature": record.context_signature,
                }
            )
            pending.append(issue)

        if not pending:
            self._global_validation_state = {
                "pending_new_issues": [],
                "issues": [],
                "observations": [],
                "notes": ["Scan-level validation queue had no open obligations."],
            }
            return

        helper = Analyzer(
            self.base_config,
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            user_config=self.user_config,
            force_ignore_history=self.force_ignore_history,
            maintain_mode=self.maintain_mode,
            candidate_ledger=self._candidate_ledger,
            # The queue only validates frozen candidate evidence.  It must not
            # trigger a second semantic-discovery build after all entry
            # workers have already completed one.
            shared_local_pattern_semantics=self._shared_local_pattern_semantics,
            shared_semantic_overlay=self._shared_semantic_overlay,
            llm_clients=self._shared_llm_clients,
            validation_result_cache=self._validation_result_cache,
            cancellation_token=self._cancellation_token,
            scheduler=self._scheduler,
            candidate_ir_persistence_lock=self._candidate_ir_persistence_lock,
            decision_fact_cache=self._decision_fact_cache,
            write_root_reports=False,
            defer_validation_to_scan=False,
        )
        ledger_records = list(self._candidate_ledger.records())
        raw_occurrence_count = sum(
            len(record.occurrence_uids)
            for record in ledger_records
        )
        eligible_records = [
            record
            for record in ledger_records
            if str(record.decision_context_version or "").endswith(("v3.1", "v3.2"))
            and record.record_role == "validation_obligation"
        ]
        eligible_occurrence_count = sum(
            len(record.occurrence_uids) for record in eligible_records
        )
        eligible_duplicate_request_count = sum(
            max(0, len(record.occurrence_uids) - 1)
            for record in eligible_records
        )
        state: Dict[str, Any] = {
            "entry_func": "__batch__",
            "entry_identity": "__batch__",
            "entry_index_name": "",
            "agent_context": {"func_name": "__batch__", "code": ""},
            "pending_new_issues": pending,
            "issues": [],
            "observations": [],
            "notes": [],
            "candidate_ledger": self._candidate_ledger,
            "scan_level_raw_occurrence_count": raw_occurrence_count,
            "eligible_alias_occurrence_count": eligible_occurrence_count,
            "eligible_validation_group_count": len(eligible_records),
            # Only already-proven structural aliases participate in this
            # denominator.  The ledger creates one record for a shared future,
            # so every alias here avoided a second Validator invocation.
            "eligible_duplicate_request_count": eligible_duplicate_request_count,
            "coalesced_duplicate_request_count": eligible_duplicate_request_count,
            "cluster_fragmentation_by_reason": {},
        }
        started = time.monotonic()
        logger.info(
            "[validation-queue] start unique_groups=%d raw_occurrences=%d",
            len(pending),
            raw_occurrence_count,
        )
        helper.validation_runner.run(state)
        self._global_validation_duration_seconds = max(
            0.0, time.monotonic() - started
        )
        self._global_validation_state = state
        logger.info(
            "[validation-queue] end unique_groups=%d confirmed=%d review=%d duration=%.2fs",
            len(pending),
            len(state["issues"]),
            len(state["observations"]),
            self._global_validation_duration_seconds,
        )

    @staticmethod
    def _scan_budget_metadata(
        *,
        duration_seconds: float,
        budget_seconds: Optional[float],
        policy: str,
    ) -> Dict[str, Any]:
        try:
            normalized_budget = (
                float(budget_seconds) if budget_seconds is not None else None
            )
        except (TypeError, ValueError):
            normalized_budget = None
        if normalized_budget is not None and normalized_budget <= 0:
            normalized_budget = None
        duration = max(0.0, float(duration_seconds or 0.0))
        exceeded = (
            normalized_budget is not None and duration > normalized_budget
        )
        overrun = (
            max(0.0, duration - normalized_budget)
            if normalized_budget is not None
            else 0.0
        )
        return {
            "scan_budget_seconds": normalized_budget,
            "scan_budget_exceeded": exceeded,
            "scan_budget_overrun_seconds": round(overrun, 3),
            "budget_exhaustion_policy": str(policy or "observe"),
        }

    def _run_global_modeling(self, entries: List[FunctionEntry]) -> bool:
        started = time.time()
        logger.info("[global-model] start entries=%d", len(entries))
        try:
            helper = Analyzer(
                self.base_config,
                code_index=self.code_index,
                snapshot_store=self.snapshot_store,
                user_config=self.user_config,
                force_ignore_history=self.force_ignore_history,
                maintain_mode=self.maintain_mode,
                candidate_ledger=self._candidate_ledger,
                shared_local_pattern_semantics=self._get_shared_local_pattern_semantics(),
                shared_semantic_overlay=self._get_shared_semantic_overlay(),
                llm_clients=self._shared_llm_clients,
                validation_result_cache=self._validation_result_cache,
                cancellation_token=self._cancellation_token,
                scheduler=self._scheduler,
                decision_fact_cache=self._decision_fact_cache,
                write_root_reports=False,
            )
            modeler = GlobalModeler.from_analyzer_helpers(
                self.base_config,
                self.code_index,
                self.snapshot_store,
                self.user_config,
                llm_clients=self._shared_llm_clients,
                tools_factory=helper._get_tools,
                tool_policy_factory=helper._tool_policy_for_agent,
                attach_contract=helper._attach_agent_contract,
                scheduler=self._scheduler,
            )
            with bind_cancellation_token(self._cancellation_token):
                self._cancellation_token.raise_if_cancelled()
                stats = modeler.run(entries)
            self._last_global_model_stats = stats.to_dict()
            logger.info(
                "[global-model] end entries=%d reachable=%d modeled=%d cache_hits=%d "
                "deterministic=%d llm=%d failed=%d unresolved_entries=%d "
                "reconciled=%d reconcile_failed=%d duration=%.2fs",
                len(entries),
                stats.reachable_functions,
                stats.modeled_functions,
                stats.cache_hit_functions,
                stats.deterministic_snapshot_count,
                stats.llm_snapshot_count,
                stats.failed_functions,
                stats.unresolved_entry_functions,
                stats.reconciled_functions,
                stats.reconciliation_failures,
                time.time() - started,
            )
            if not stats.stage_complete:
                logger.error(
                    "[global-model] stage gate rejected entry fan-out "
                    "failed=%d unresolved_entries=%d reconcile_failed=%d",
                    stats.failed_functions,
                    stats.unresolved_entry_functions,
                    stats.reconciliation_failures,
                )
                return False
            return True
        except Exception as exc:
            self._last_global_model_stats = {"error": str(exc)}
            logger.exception("[global-model] failed before entry fan-out.")
            return False

    def _run_project_deterministic_fact_pass(
        self,
        entries: List[FunctionEntry],
    ) -> None:
        """Collect local deterministic facts once for the union of entry reachability.

        The ordinary entry workers still own caller-specific context and report
        projection.  This pass owns only cheap function-local collection: it
        traverses the complete reachable union without an LLM skill filter or
        a per-entry depth quota, then registers each result against the entry
        path that reached it.  Ledger identity coalesces those paths before a
        Validator can run.
        """

        started = time.monotonic()
        state: Dict[str, Any] = {
            "enabled": True,
            "status": "complete",
            "reachable_functions": 0,
            "analyzed_functions": 0,
            "candidate_count": 0,
            "unresolved_internal_functions": 0,
            "failures": [],
        }
        generator = ClangAstCfgCandidateGenerator(
            self._get_shared_local_pattern_semantics(),
            semantic_overlay=self._get_shared_semantic_overlay(),
            tooling_evidence_provider=None,
        )
        helper = Analyzer(
            self.base_config,
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            user_config=self.user_config,
            force_ignore_history=self.force_ignore_history,
            maintain_mode=self.maintain_mode,
            candidate_ledger=self._candidate_ledger,
            shared_local_pattern_semantics=self._get_shared_local_pattern_semantics(),
            shared_semantic_overlay=self._get_shared_semantic_overlay(),
            llm_clients=self._shared_llm_clients,
            validation_result_cache=self._validation_result_cache,
            cancellation_token=self._cancellation_token,
            scheduler=self._scheduler,
            decision_fact_cache=self._decision_fact_cache,
            write_root_reports=False,
            defer_validation_to_scan=True,
        )

        # Keep one call path per (entry, function) to avoid exponential path
        # expansion in recursive dispatcher graphs.  The fact collection is
        # function-scoped; all extra paths remain discoverable through normal
        # entry analysis and will attach as aliases to the same obligation.
        pending: List[tuple[str, str, str, List[str]]] = []
        for entry in entries:
            identity = entry.identity_key(self.base_config.project.project_root)
            pending.append(
                (
                    entry.function_name,
                    str(entry.file_path or ""),
                    identity,
                    [entry.function_name],
                )
            )
        seen_routes: Set[tuple[str, str, str]] = set()
        implementations: Dict[str, Dict[str, Any]] = {}
        routes: Dict[str, List[tuple[str, List[str]]]] = {}

        while pending:
            self._cancellation_token.raise_if_cancelled()
            function, file_hint, entry_identity, call_path = pending.pop(0)
            route_key = (entry_identity, function, file_hint)
            if route_key in seen_routes:
                continue
            seen_routes.add(route_key)
            try:
                impl = self.code_index.get_function_impl(
                    function,
                    max_lines=None,
                    warn_missing=False,
                    file_path=file_hint,
                )
            except Exception as exc:
                state["failures"].append(
                    {
                        "function": function,
                        "entry_identity": entry_identity,
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            if not impl:
                # Calls into a system library or unresolved indirect callback
                # are retained as coverage telemetry, not fabricated failures.
                state["unresolved_internal_functions"] += 1
                continue
            index_name = str(
                impl.get("index_name")
                or impl.get("qualified_name")
                or f"{impl.get('file') or file_hint}::{function}"
            )
            implementations.setdefault(index_name, impl)
            route_list = routes.setdefault(index_name, [])
            if (entry_identity, call_path) not in route_list:
                route_list.append((entry_identity, call_path))
            try:
                callees = self.code_index.get_callees(function, limit=1_000_000)
            except Exception as exc:
                state["failures"].append(
                    {
                        "function": function,
                        "entry_identity": entry_identity,
                        "reason": f"callee_query:{type(exc).__name__}: {exc}",
                    }
                )
                continue
            for callee in callees:
                if not isinstance(callee, dict):
                    continue
                callee_name = str(
                    callee.get("name")
                    or callee.get("function")
                    or callee.get("callee")
                    or ""
                ).strip()
                if not callee_name or callee_name in call_path:
                    continue
                pending.append(
                    (
                        callee_name,
                        str(callee.get("file") or callee.get("file_path") or ""),
                        entry_identity,
                        [*call_path, callee_name],
                    )
                )

        state["reachable_functions"] = len(implementations)
        for index_name, impl in sorted(implementations.items()):
            self._cancellation_token.raise_if_cancelled()
            # CodeIndex exposes this as ``func_name``.  Accept legacy test/
            # backend aliases as compatibility fallbacks, but never mark a
            # complete implementation failed merely because its display key
            # differs from the index record schema.
            function = str(
                impl.get("func_name")
                or impl.get("qualified_name")
                or impl.get("name")
                or impl.get("function")
                or ""
            )
            if not function:
                # CodeIndex index names include source coordinates, but an
                # empty source function is not analysable evidence.
                state["failures"].append(
                    {"function": index_name, "reason": "implementation_missing_function_name"}
                )
                continue
            try:
                findings = generator.generate_issues(
                    function,
                    str(impl.get("code") or ""),
                    str(impl.get("file") or ""),
                    # No ``allowed_skills``: deterministic fact collection is
                    # never a lossy task-router filter.
                    allowed_skills=None,
                )
            except Exception as exc:
                state["failures"].append(
                    {
                        "function": function,
                        "reason": f"candidate_generation:{type(exc).__name__}: {exc}",
                    }
                )
                continue
            state["analyzed_functions"] += 1
            for entry_identity, call_path in routes.get(index_name, []):
                emitted = []
                for finding in findings:
                    issue = deepcopy(finding)
                    issue["entry_identity"] = entry_identity
                    issue["call_path"] = list(call_path)
                    issue["internal_sink_lifted"] = len(call_path) > 1
                    issue["project_fact_pass_v1"] = True
                    emitted.append(issue)
                if emitted:
                    helper._register_candidate_issues(
                        {
                            "candidate_ledger": self._candidate_ledger,
                            "entry_identity": entry_identity,
                            "run_id": self.run_id,
                        },
                        emitted,
                        source="project_deterministic_fact_pass",
                    )
                    state["candidate_count"] += len(emitted)

        if state["failures"]:
            state["status"] = "failed"
        state["duration_seconds"] = round(time.monotonic() - started, 4)
        self._project_fact_pass_state = state
        logger.info(
            "[project-facts] end reachable=%d analyzed=%d candidates=%d unresolved=%d failures=%d duration=%.2fs",
            state["reachable_functions"],
            state["analyzed_functions"],
            state["candidate_count"],
            state["unresolved_internal_functions"],
            len(state["failures"]),
            state["duration_seconds"],
        )

    @staticmethod
    def _build_shared_llm_clients(config: ZScopeConfig) -> Dict[str, LLMClient]:
        clients: Dict[str, LLMClient] = {}
        for name, llm_cfg in config.llms.items():
            effective_timeout = minimum_optional_positive_seconds(
                llm_cfg.timeout,
                getattr(
                    config.analysis,
                    "request_deadline_seconds",
                    None,
                ),
            )
            clients[name] = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=effective_timeout,
                max_retries=llm_cfg.max_retries,
                retry_until_available=getattr(
                    llm_cfg, "retry_until_available", False
                ),
                max_tokens=llm_cfg.max_tokens,
                base_url_rate_limit_per_minute=getattr(
                    llm_cfg, "base_url_rate_limit_per_minute", 0
                ),
                base_url_max_concurrent_requests=getattr(
                    llm_cfg, "base_url_max_concurrent_requests", 0
                ),
                global_max_concurrent_requests=getattr(
                    config.analysis, "llm_max_inflight", 8
                ),
                supports_structured_output=getattr(
                    llm_cfg, "supports_structured_output", False
                ),
            )
        return clients

    def _prioritize_entries_for_execution(self, entries: List[FunctionEntry]) -> List[FunctionEntry]:
        """Schedule likely long-running entries first to reduce batch tail idle time."""
        if len(entries) <= 1:
            return list(entries)

        scored = [
            (self._entry_scheduling_score(entry), index, entry)
            for index, entry in enumerate(entries)
        ]
        scored.sort(key=lambda item: (-item[0], item[1]))
        prioritized = [entry for _score, _index, entry in scored]
        if [entry.function_name for entry in prioritized] != [entry.function_name for entry in entries]:
            preview = ", ".join(
                f"{entry.function_name}:{score}"
                for score, _index, entry in scored[: min(8, len(scored))]
            )
            logger.info("[entry-worker] prioritized entry schedule top=%s", preview)
        return prioritized

    def _entry_scheduling_score(self, entry: FunctionEntry) -> int:
        score = 0
        exposure = str(getattr(entry, "exposure", "") or "").strip().lower()
        score += _ENTRY_EXPOSURE_WEIGHTS.get(exposure, 0)
        reason_text = " ".join(str(reason) for reason in getattr(entry, "reasons", []) or [])
        metadata_text = " ".join(
            part
            for part in (
                str(entry.custom_prompt or ""),
                exposure,
                reason_text,
            )
            if part
        )
        if _ENTRY_HEAVY_TEXT_RE.search(metadata_text):
            score += 80

        try:
            impl = self.code_index.get_function_impl(
                entry.function_name,
                max_lines=self.base_config.analysis.max_function_lines,
                include_context=False,
                warn_missing=False,
                file_path=str(entry.file_path or ""),
            )
        except Exception as exc:
            logger.debug(
                "Unable to estimate scheduling cost for '%s': %s",
                entry.function_name,
                exc,
            )
            impl = None

        if isinstance(impl, dict):
            code = str(impl.get("code") or "")
            code_without_entry_name = re.sub(
                rf"\b{re.escape(entry.function_name)}\b",
                "",
                code,
            )
            line_count = max(0, len(code.splitlines()))
            score += min(600, line_count * 4)
            call_names = {
                name
                for name in _ENTRY_CALL_RE.findall(code_without_entry_name)
                if name
                and name
                not in {"if", "for", "while", "switch", "return", "sizeof"}
            }
            score += min(360, len(call_names) * 18)
            score += min(220, len(_ENTRY_CONTROL_RE.findall(code_without_entry_name)) * 12)
            score += min(260, len(_ENTRY_HEAVY_TEXT_RE.findall(code_without_entry_name)) * 18)
        return int(score)

    @staticmethod
    def _entry_result_key(entry: FunctionEntry) -> str:
        focus = entry.diff_focus if isinstance(entry.diff_focus, dict) else {}
        component = str(focus.get("component") or "").strip()
        file_path = FunctionEntry._portable_path_text(
            entry.file_path or focus.get("entry_file_path") or ""
        )
        signature = FunctionEntry.normalize_signature(entry.signature)
        if component or file_path or signature:
            key = f"{component or 'default'}:{entry.function_name}@{file_path or '<unknown>'}"
            if signature:
                key = f"{key}::{signature}"
            return key
        return entry.function_name

    def _materialize_entry_identities(
        self,
        entries: List[FunctionEntry],
    ) -> List[FunctionEntry]:
        """Resolve legacy name-only entries into file+signature identities."""
        project_root = self.base_config.project.project_root
        getter = getattr(self.code_index, "get_function_impl", None)
        identity_finder = getattr(self.code_index, "find_function_identities", None)
        resolved_entries: List[FunctionEntry] = []
        seen_identities: Set[str] = set()
        for entry in entries:
            file_path = entry.normalized_file_path(project_root)
            resolved = replace(entry, file_path=file_path or None)
            impl: Optional[Dict[str, Any]] = None
            if callable(identity_finder):
                try:
                    matches = identity_finder(
                        resolved.lookup_query(),
                        file_path=file_path,
                    )
                except TypeError:
                    matches = identity_finder(resolved.lookup_query())
                except Exception as exc:
                    logger.debug(
                        "Unable to query entry identity for %s: %s",
                        resolved.function_name,
                        exc,
                    )
                    matches = []
                identity_matches = [
                    match for match in matches
                    if isinstance(match, dict)
                ] if isinstance(matches, list) else []
                if identity_matches:
                    for match in identity_matches:
                        matched_entry = self._entry_from_identity_record(
                            resolved,
                            match,
                            project_root,
                        )
                        identity = matched_entry.identity_key(project_root)
                        if identity in seen_identities:
                            continue
                        seen_identities.add(identity)
                        resolved_entries.append(matched_entry)
                    continue
            if impl is None and callable(getter):
                try:
                    impl = getter(
                        resolved.lookup_query(),
                        max_lines=None,
                        include_context=False,
                        warn_missing=False,
                        file_path=file_path,
                    )
                except TypeError:
                    try:
                        impl = getter(resolved.lookup_query(), include_context=False)
                    except TypeError:
                        impl = getter(resolved.lookup_query())
                except Exception as exc:
                    logger.debug(
                        "Unable to resolve entry identity for %s: %s",
                        resolved.function_name,
                        exc,
                    )
                    impl = None
            if isinstance(impl, dict):
                resolved = self._entry_from_identity_record(
                    resolved,
                    {
                        "function_name": impl.get("func_name"),
                        "file_path": impl.get("file"),
                        "signature": impl.get("signature"),
                    },
                    project_root,
                )
            identity = resolved.identity_key(project_root)
            if identity in seen_identities:
                continue
            seen_identities.add(identity)
            resolved_entries.append(resolved)
        return resolved_entries

    @staticmethod
    def _entry_from_identity_record(
        entry: FunctionEntry,
        record: Dict[str, Any],
        project_root: Path,
    ) -> FunctionEntry:
        file_path = FunctionEntry(
            function_name=entry.function_name,
            file_path=str(record.get("file_path") or entry.file_path or ""),
        ).normalized_file_path(project_root)
        return replace(
            entry,
            function_name=str(
                record.get("function_name") or entry.function_name
            ),
            file_path=file_path or None,
            signature=str(
                record.get("signature") or entry.signature or ""
            )
            or None,
        )
    
    def analyze_functions(
        self, 
        function_names: List[str],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> Dict[str, ParallelAnalysisResult]:
        """
        Analyze multiple functions in parallel.
        
        Args:
            function_names: List of function names to analyze
            progress_callback: Optional callback(completed, total, func_name) for progress
            
        Returns:
            Dict mapping function name to analysis result
        """
        # Convert to FunctionEntry objects
        entries = [FunctionEntry(function_name=name) for name in function_names]
        return self.analyze_function_entries(entries, progress_callback)

    
    def _analyze_single_entry(self, entry: FunctionEntry) -> ParallelAnalysisResult:
        """Analyze a single function entry with optional custom prompt."""
        start_time = time.monotonic()
        entry_key = self._entry_result_key(entry)
        entry_budget_seconds = getattr(
            self.base_config.analysis,
            "entry_deadline_seconds",
            1800.0,
        )
        budget_exhaustion_policy = "observe"
        logger.info(
            "[entry-worker] start entry=%s key=%s file=%s",
            entry.function_name,
            entry_key,
            entry.file_path or "",
        )
        entry_token = self._cancellation_token.child(
            timeout_seconds=None
        )
        
        try:
            # Create a config copy with this function as entry point and custom prompt
            phase_started = time.time()
            config_copy = self._create_config_for_entry(entry)
            logger.info(
                "[entry-worker] config-ready entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - phase_started,
            )
            
            # Create analyzer and run with shared components
            phase_started = time.time()
            analyzer = Analyzer(
                 config_copy,
                 code_index=self.code_index,
                 snapshot_store=self.snapshot_store,
                 user_config=self.user_config,
                 force_ignore_history=self.force_ignore_history,
                 maintain_mode=self.maintain_mode,
                 candidate_ledger=self._candidate_ledger,
                 shared_local_pattern_semantics=(
                     None if self.maintain_mode else self._get_shared_local_pattern_semantics()
                 ),
                 shared_semantic_overlay=(
                     None if self.maintain_mode else self._get_shared_semantic_overlay()
                 ),
                 llm_clients=self._shared_llm_clients,
                 validation_result_cache=self._validation_result_cache,
                 cancellation_token=entry_token,
                 scheduler=self._scheduler,
                candidate_ir_persistence_lock=self._candidate_ir_persistence_lock,
                decision_fact_cache=self._decision_fact_cache,
                write_root_reports=False,
                 defer_validation_to_scan=self._uses_scan_validation_queue(),
            )
            logger.info(
                "[entry-worker] analyzer-ready entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - phase_started,
            )
            run_started = time.time()
            logger.info(
                "[entry-worker] run-start entry=%s key=%s",
                entry.function_name,
                entry_key,
            )
            report_dict = analyzer.run()
            report_metadata = (
                dict(report_dict.get("metadata", {}))
                if isinstance(report_dict.get("metadata"), dict)
                else {}
            )
            logger.info(
                "[entry-worker] run-end entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - run_started,
            )
            
            duration = time.monotonic() - start_time
            budget_metadata = self._entry_budget_metadata(
                duration_seconds=duration,
                budget_seconds=entry_budget_seconds,
                policy=budget_exhaustion_policy,
            )
            report_metadata.update(budget_metadata)
            if budget_metadata["entry_budget_exceeded"]:
                logger.warning(
                    "[entry-worker] budget-exceeded entry=%s key=%s "
                    "budget=%.2fs overrun=%.2fs policy=%s outcome=completed",
                    entry.function_name,
                    entry_key,
                    float(entry_budget_seconds),
                    budget_metadata["entry_budget_overrun_seconds"],
                    budget_exhaustion_policy,
                )
            logger.info(
                "[entry-worker] end entry=%s key=%s verdict=%s issues=%d duration=%.2fs",
                entry.function_name,
                entry_key,
                report_dict.get("overall_verdict", "unknown"),
                len(report_dict.get("issues", [])),
                duration,
            )
            
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict=report_dict.get("overall_verdict", "unknown"),
                entry_identity=entry.identity_key(
                    self.base_config.project.project_root
                ),
                entry_file_path=entry.normalized_file_path(
                    self.base_config.project.project_root
                ),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                issues=report_dict.get("issues", []),
                audit_observations=report_metadata.get("audit_observations", []),
                candidate_terminal_states=report_dict.get(
                    "candidate_terminal_states", []
                ),
                error=(
                    str(report_dict.get("error"))
                    if report_dict.get("error")
                    else None
                ),
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata[
                    "entry_budget_overrun_seconds"
                ],
                budget_exhaustion_policy=budget_exhaustion_policy,
                context_tokens=report_metadata.get("context_tokens", 0),
                cumulative_prompt_tokens=report_metadata.get("cumulative_prompt_tokens", 0),
                cumulative_completion_tokens=report_metadata.get("cumulative_completion_tokens", 0),
                cumulative_total_tokens=report_metadata.get("cumulative_total_tokens", 0),
                diff_focus=entry.diff_focus,
                metadata=report_metadata,
            )
            
        except CancellationError as e:
            duration = time.monotonic() - start_time
            reason = entry_token.reason or str(e) or "entry_cancelled"
            budget_metadata = self._entry_budget_metadata(
                duration_seconds=duration,
                budget_seconds=entry_budget_seconds,
                policy=budget_exhaustion_policy,
                force_exceeded=False,
            )
            budget_metadata["cancellation_reason"] = reason
            logger.warning(
                "[entry-worker] cancelled entry=%s key=%s reason=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                reason,
                duration,
            )
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict="error",
                entry_identity=entry.identity_key(
                    self.base_config.project.project_root
                ),
                entry_file_path=entry.normalized_file_path(
                    self.base_config.project.project_root
                ),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                error=reason,
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata[
                    "entry_budget_overrun_seconds"
                ],
                budget_exhaustion_policy=budget_exhaustion_policy,
                diff_focus=entry.diff_focus,
                metadata=budget_metadata,
            )
        except Exception as e:
            duration = time.monotonic() - start_time
            budget_metadata = self._entry_budget_metadata(
                duration_seconds=duration,
                budget_seconds=entry_budget_seconds,
                policy=budget_exhaustion_policy,
            )
            logger.exception(
                "[entry-worker] error entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                duration,
            )
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict="error",
                entry_identity=entry.identity_key(
                    self.base_config.project.project_root
                ),
                entry_file_path=entry.normalized_file_path(
                    self.base_config.project.project_root
                ),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                error=str(e),
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata[
                    "entry_budget_overrun_seconds"
                ],
                budget_exhaustion_policy=budget_exhaustion_policy,
                diff_focus=entry.diff_focus,
                metadata=budget_metadata,
            )
        finally:
            self._close_thread_llm_sessions()

    @staticmethod
    def _entry_budget_metadata(
        *,
        duration_seconds: float,
        budget_seconds: Optional[float],
        policy: str,
        force_exceeded: bool = False,
    ) -> Dict[str, Any]:
        normalized_budget = (
            float(budget_seconds)
            if budget_seconds is not None and float(budget_seconds) > 0
            else None
        )
        overrun_seconds = (
            max(0.0, float(duration_seconds) - normalized_budget)
            if normalized_budget is not None
            else 0.0
        )
        exceeded = bool(
            normalized_budget is not None
            and (force_exceeded or overrun_seconds > 0.0)
        )
        return {
            "entry_budget_seconds": normalized_budget,
            "entry_budget_exceeded": exceeded,
            "entry_budget_overrun_seconds": overrun_seconds,
            "budget_exhaustion_policy": str(policy or "observe"),
            "entry_budget": {
                "seconds": normalized_budget,
                "exceeded": exceeded,
                "overrun_seconds": overrun_seconds,
                "policy": str(policy or "observe"),
            },
        }
    
    def _close_thread_llm_sessions(self) -> None:
        seen: Set[int] = set()
        for client in self._shared_llm_clients.values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_thread_session = getattr(client, "close_thread_session", None)
            if callable(close_thread_session):
                close_thread_session()

    def close(self) -> None:
        scheduler = getattr(self, "_scheduler", None)
        if scheduler is not None:
            scheduler.shutdown(wait=True, cancel_futures=True)
        seen: Set[int] = set()
        for client in getattr(self, "_shared_llm_clients", {}).values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_client = getattr(client, "close", None)
            if callable(close_client):
                close_client()

    def _prepare_shared_semantics(self) -> None:
        """Warm shared project semantics before entry-level analyzers fan out."""
        self._get_shared_local_pattern_semantics()
        self._get_shared_semantic_overlay()

    def _get_shared_local_pattern_semantics(self) -> LocalPatternSemantics:
        if self._shared_local_pattern_semantics is None:
            with self._shared_semantics_lock:
                if self._shared_local_pattern_semantics is None:
                    self._shared_local_pattern_semantics = LocalPatternSemanticBuilder(
                        self.code_index,
                        self.user_config,
                        self.snapshot_store,
                        self.base_config.project.exclude_paths,
                    ).build()
        return self._shared_local_pattern_semantics

    def _get_shared_semantic_overlay(self) -> Dict[str, Any]:
        if self._shared_semantic_overlay is None:
            with self._shared_semantics_lock:
                if self._shared_semantic_overlay is None:
                    self._shared_semantic_overlay = SemanticOverlayCompiler(self.user_config).compile()
        return self._shared_semantic_overlay

    def _create_config_for_entry(self, entry: FunctionEntry) -> ZScopeConfig:
        """Create a ZScopeConfig copy with the specified entry and custom prompt."""

        agents = []
        for agent_cfg in self.base_config.project.agents:
            agent_copy = copy(agent_cfg)
            entry_custom_prompt = agent_cfg.entry_custom_prompt
            if entry.custom_prompt and agent_cfg.name == "vulnerability_analyzer":
                entry_custom_prompt = entry.custom_prompt
            agent_copy.entry_custom_prompt = entry_custom_prompt
            agents.append(agent_copy)

        project = copy(self.base_config.project)
        project.entry_function = entry.function_name
        project.entry_file_path = entry.file_path
        project.entry_signature = entry.signature
        project.entry_diff_focus = entry.diff_focus
        project.agents = agents

        config = copy(self.base_config)
        config.project = project
        # Keep entry-specific focus separate from the configured task so skill
        # routing remains driven by the global vulnerability scope.
        return config
    

    def generate_combined_report(
        self, 
        results: Dict[str, ParallelAnalysisResult],
        output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate a combined report from all parallel analysis results.
        
        Args:
            results: Dict of function name to analysis result
            output_path: Optional path to save combined report
            
        Returns:
            Combined report dict
        """
        all_issues = []
        all_observations = []
        all_terminal_states: List[Dict[str, Any]] = []
        function_summaries = []
        total_duration = 0.0
        base_config = getattr(self, "base_config", None)
        project_config = getattr(base_config, "project", None)
        project_root = str(getattr(project_config, "project_root", "") or "")
        project_id = str(
            getattr(project_config, "project_id", "")
            or Path(project_root).name
            or "project"
        )
        source_root = str(getattr(project_config, "source_root", "") or "")
        batch_run_id = str(getattr(self, "run_id", "") or "")
        all_terminal_states.extend(
            self._deferred_entry_terminal_states(project_id, project_root)
        )
        
        for entry_key, result in results.items():
            total_duration += result.duration_seconds
            all_terminal_states.extend(
                item
                for item in result.candidate_terminal_states
                if isinstance(item, dict)
            )
            validation_performance = (
                result.metadata.get("validation_performance", {})
                if isinstance(result.metadata, dict)
                else {}
            )
            
            function_summaries.append({
                "function": result.function_name,
                "entry_key": entry_key,
                "entry_identity": result.entry_identity or entry_key,
                "entry_file_path": result.entry_file_path,
                "entry_signature": result.entry_signature,
                "verdict": result.verdict,
                "issue_count": len(result.issues),
                "audit_observation_count": len(result.audit_observations),
                "duration_seconds": round(result.duration_seconds, 2),
                "entry_budget_seconds": result.entry_budget_seconds,
                "entry_budget_exceeded": result.entry_budget_exceeded,
                "entry_budget_overrun_seconds": round(
                    result.entry_budget_overrun_seconds, 3
                ),
                "budget_exhaustion_policy": result.budget_exhaustion_policy,
                "context_tokens": result.context_tokens,
                "cumulative_prompt_tokens": result.cumulative_prompt_tokens,
                "cumulative_completion_tokens": result.cumulative_completion_tokens,
                "cumulative_total_tokens": result.cumulative_total_tokens,
                "validation_performance": validation_performance,
                "error": result.error
            })
            
            # Add function context to each issue
            for issue in result.issues:
                issue_copy = issue.copy()
                issue_copy.setdefault("analyzed_from", result.function_name)
                issue_copy.setdefault("reported_from_entry", result.entry_identity or entry_key)
                issue_copy.setdefault("entry_identity", result.entry_identity or entry_key)
                if result.entry_file_path:
                    issue_copy["entry_file_path"] = result.entry_file_path
                if result.entry_signature:
                    issue_copy["entry_signature"] = result.entry_signature
                if entry_key != result.function_name:
                    issue_copy["entry_key"] = entry_key
                self._annotate_diff_relevance(issue_copy, result.diff_focus)
                annotate_issue_identity(
                    issue_copy,
                    project_id=project_id,
                    project_root=project_root,
                    revision=str(result.metadata.get("commit_sha") or ""),
                    entry_function=result.entry_identity or entry_key,
                    run_id=batch_run_id,
                    ordinal=len(all_issues),
                    default_disposition="confirmed",
                )
                all_issues.append(issue_copy)
            for observation in result.audit_observations:
                observation_copy = observation.copy()
                observation_copy.setdefault("analyzed_from", result.function_name)
                observation_copy.setdefault(
                    "reported_from_entry",
                    result.entry_identity or entry_key,
                )
                observation_copy.setdefault(
                    "entry_identity",
                    result.entry_identity or entry_key,
                )
                if result.entry_file_path:
                    observation_copy["entry_file_path"] = result.entry_file_path
                if result.entry_signature:
                    observation_copy["entry_signature"] = result.entry_signature
                if entry_key != result.function_name:
                    observation_copy["entry_key"] = entry_key
                self._annotate_diff_relevance(observation_copy, result.diff_focus)
                annotate_issue_identity(
                    observation_copy,
                    project_id=project_id,
                    project_root=project_root,
                    revision=str(result.metadata.get("commit_sha") or ""),
                    entry_function=result.entry_identity or entry_key,
                    run_id=batch_run_id,
                    ordinal=len(all_observations),
                    default_disposition="needs_review",
                )
                all_observations.append(observation_copy)
        
        # The scan-level ledger is the final lifecycle authority. Entry reports
        # can be assembled while a shared validation is still in flight, so
        # replace their v3 terminal projection with one final atomic snapshot.
        ledger_snapshot: Dict[str, Any] = {}
        snapshot = getattr(
            getattr(self, "_candidate_ledger", None),
            "freeze",
            None,
        )
        if callable(snapshot):
            ledger_snapshot = snapshot()
        final_records = [
            item
            for item in ledger_snapshot.get("records", [])
            if isinstance(item, dict)
        ]
        final_by_cluster = {
            str(item.get("validation_cluster_uid") or ""): item
            for item in final_records
            if item.get("validation_cluster_uid")
        }
        canonical_outcomes = ReportAssembler._canonical_outcome_items(
            {"candidate_lifecycle_snapshot": ledger_snapshot}
        )
        analysis_config = getattr(base_config, "analysis", None)
        canonical_projection = bool(
            getattr(analysis_config, "candidate_lifecycle_v3", True)
        ) and bool(
            getattr(analysis_config, "canonical_outcome_projection", True)
        # A missing/empty ledger snapshot is not a canonical outcome set.
        # This happens in compatibility callers and lightweight report-only
        # flows; dropping their ordinary findings would be a false clean scan.
        ) and bool(canonical_outcomes)
        if canonical_projection:
            # A scan-level outcome is authoritative.  Per-entry reports may
            # have been assembled before another entry completed the shared
            # validation future, so they are provenance only at this point.
            all_issues = [
                item
                for item in canonical_outcomes
                if str(item.get("candidate_disposition") or "").lower()
                == "confirmed"
            ]
            all_observations = [
                item
                for item in canonical_outcomes
                if str(item.get("candidate_disposition") or "").lower()
                == "needs_review"
            ]
            all_terminal_states = [
                {
                    key: value
                    for key, value in item.items()
                    if key != "issue" and value not in (None, "", [], {})
                }
                for item in canonical_outcomes
            ]
        elif final_by_cluster:
            all_observations = [
                item
                for item in all_observations
                if (
                    not item.get("validation_cluster_uid")
                    or str(
                        final_by_cluster.get(
                            str(item.get("validation_cluster_uid") or ""),
                            {},
                        ).get("candidate_disposition")
                        or ""
                    ).lower()
                    == "needs_review"
                )
            ]
            all_terminal_states = [
                item
                for item in all_terminal_states
                if not item.get("validation_cluster_uid")
            ]
            all_terminal_states.extend(final_records)
            all_observations.extend(
                ReportAssembler._unresolved_candidate_observations(
                    {"candidate_lifecycle_snapshot": ledger_snapshot},
                    list(all_issues) + list(all_observations),
                )
            )

        # Deduplicate confirmed issues with the same final-report semantics used
        # by single-entry reports. Observations stay programmatic to avoid an
        # extra batch LLM pass over needs_review-only material.
        interrupted = bool(getattr(self, "_interrupted", False))
        if canonical_projection:
            unique_issues = list(all_issues)
            semantic_dedup_summary = {
                "input_count": len(all_issues),
                "after_programmatic_count": len(all_issues),
                "final_count": len(all_issues),
                "llm_enabled": False,
                "canonical_projection": True,
            }
        else:
            unique_issues, semantic_dedup_summary = self._deduplicate_report_issues(
                all_issues,
                allow_llm=not interrupted,
            )
        review_observations = (
            list(all_observations)
            if canonical_projection
            else coalesce_review_observations(all_observations)
        )
        review_fingerprints = {
            str(item.get("validation_cluster_uid") or "")
            or str(item.get("candidate_uid") or "")
            for item in review_observations
        }
        non_review_observations = [
            item
            for item in all_observations
            if not (
                str(item.get("validation_cluster_uid") or "")
                or str(item.get("candidate_uid") or "")
            )
            in review_fingerprints
        ]
        unique_observations = (
            review_observations
            if canonical_projection
            else self._deduplicate_issues(non_review_observations) + review_observations
        )
        unique_terminal_states = [
            dict(item)
            for item in coalesce_terminal_candidates(all_terminal_states)
            if isinstance(item, dict)
        ]
        report_views = build_report_views(
            unique_issues,
            unique_observations,
            canonical_projection=canonical_projection,
        )
        view_summary = report_view_summary({"report_views": report_views})
        with_review_view = report_views.get("with_needs_review", {})
        
        diff_relevance_summary = self._diff_relevance_summary(unique_issues, unique_observations)
        diff_coverage = self._diff_coverage_metadata()
        global_validation_state = dict(
            getattr(self, "_global_validation_state", {}) or {}
        )
        global_validation_duration = float(
            getattr(self, "_global_validation_duration_seconds", 0.0) or 0.0
        )
        total_duration += global_validation_duration
        batch_wall_seconds = round(float(getattr(self, "_last_batch_wall_seconds", 0.0) or 0.0), 2)
        effective_speedup = (total_duration / batch_wall_seconds) if batch_wall_seconds > 0 else 0.0
        worker_utilization = (
            effective_speedup / max(1, int(self.max_workers or 1))
            if batch_wall_seconds > 0
            else 0.0
        )
        validation_performance_summary = self._validation_performance_summary(results)
        va_candidate_coverage_summary = self._va_candidate_coverage_summary(results)
        entry_budget_summary = self._entry_budget_summary(results)
        llm_iteration_budget_summary = self._llm_iteration_budget_summary(results)
        scan_budget_summary = dict(
            getattr(self, "_last_scan_budget_metadata", {}) or {}
        )
        llm_usage_summary = self._llm_usage_summary()
        retained_prompt_tokens = sum(
            r.cumulative_prompt_tokens for r in results.values()
        )
        retained_completion_tokens = sum(
            r.cumulative_completion_tokens for r in results.values()
        )
        retained_total_tokens = sum(
            r.cumulative_total_tokens for r in results.values()
        )
        retained_prompt_tokens += int(
            global_validation_state.get("total_cumulative_prompt_tokens", 0) or 0
        )
        retained_completion_tokens += int(
            global_validation_state.get("total_cumulative_completion_tokens", 0) or 0
        )
        retained_total_tokens += int(
            global_validation_state.get("total_cumulative_total_tokens", 0) or 0
        )
        total_context_tokens = sum(r.context_tokens for r in results.values()) + int(
            global_validation_state.get("total_context_tokens", 0) or 0
        )
        response_prompt_tokens = int(
            llm_usage_summary.get("prompt_tokens") or 0
        )
        response_completion_tokens = int(
            llm_usage_summary.get("completion_tokens") or 0
        )
        response_total_tokens = int(llm_usage_summary.get("total_tokens") or 0)
        engine_capabilities = {
            entry_key: (
                result.metadata.get("engine_capabilities")
                if isinstance(result.metadata, dict)
                else {}
            )
            for entry_key, result in results.items()
        }
        project_fact_state = dict(
            getattr(self, "_project_fact_pass_state", {}) or {}
        )
        if project_fact_state:
            engine_capabilities["__project_deterministic_fact_pass__"] = {
                "project_deterministic_fact_pass": {
                    "status": str(project_fact_state.get("status") or "complete"),
                    "active": bool(project_fact_state.get("enabled", False)),
                    "candidate_count": int(project_fact_state.get("candidate_count", 0) or 0),
                    "reachable_functions": int(project_fact_state.get("reachable_functions", 0) or 0),
                    "analyzed_functions": int(project_fact_state.get("analyzed_functions", 0) or 0),
                    "unresolved_internal_functions": int(project_fact_state.get("unresolved_internal_functions", 0) or 0),
                    "failures": list(project_fact_state.get("failures") or []),
                }
            }
        error_result_count = sum(
            1
            for result in results.values()
            if bool(result.error) or str(result.verdict).lower() == "error"
        )

        combined_report = {
            "type": "parallel_analysis_report",
            "summary": {
                "functions_analyzed": len(results),
                "functions_scheduled": len(results),
                "functions_completed": len(results) - error_result_count,
                "functions_failed": error_result_count,
                "total_issues": len(unique_issues),
                "unique_issues": len(unique_issues),
                "audit_observations": len(unique_observations),
                "deferred_entry_count": len(
                    getattr(self, "deferred_entry_candidates", []) or []
                ),
                "needs_review_issues": int(
                    with_review_view.get("included_needs_review_count") or 0
                ),
                "total_issues_with_needs_review": int(
                    with_review_view.get("issue_count") or len(with_review_view.get("issues", []))
                ),
                "total_duration_seconds": round(total_duration, 2),
                "batch_wall_seconds": batch_wall_seconds,
                "total_context_tokens": total_context_tokens,
                "total_cumulative_prompt_tokens": (
                    response_prompt_tokens or retained_prompt_tokens
                ),
                "total_cumulative_completion_tokens": (
                    response_completion_tokens or retained_completion_tokens
                ),
                "total_cumulative_total_tokens": (
                    response_total_tokens or retained_total_tokens
                ),
                "retained_entry_prompt_tokens": retained_prompt_tokens,
                "retained_entry_completion_tokens": retained_completion_tokens,
                "retained_entry_total_tokens": retained_total_tokens,
                "llm_usage": llm_usage_summary,
                "parallel_speedup": f"{effective_speedup:.2f}x observed (using {self.max_workers} workers)",
                "parallel_worker_utilization": round(worker_utilization, 4),
                "diff_relevance": diff_relevance_summary["issues"],
                "diff_coverage": diff_coverage.get("coverage_summary", {}),
                "validation_performance": validation_performance_summary,
                "global_validation_queue": {
                    "enabled": self._uses_scan_validation_queue(),
                    "duration_seconds": round(global_validation_duration, 4),
                    "unique_group_count": int(
                        global_validation_state.get("validation_group_count", 0) or 0
                    ),
                    "raw_occurrence_count": int(
                        global_validation_state.get("scan_level_raw_occurrence_count", 0) or 0
                    ),
                },
                "project_deterministic_fact_pass": project_fact_state,
                "va_candidate_coverage": va_candidate_coverage_summary,
                "entry_budget": entry_budget_summary,
                "llm_iteration_budget": llm_iteration_budget_summary,
                "scan_budget": scan_budget_summary,
                "semantic_dedup": semantic_dedup_summary,
                "interrupted": interrupted,
            },
            "function_results": function_summaries,
            "issues": unique_issues,
            "issues_by_severity": self._group_by_severity(unique_issues),
            "report_views": report_views,
            "issues_with_needs_review": with_review_view.get("issues", []),
            "issues_by_severity_with_needs_review": with_review_view.get("issues_by_severity", {}),
            "candidate_terminal_states": unique_terminal_states,
            "metadata": {
                "run_id": batch_run_id,
                "repo": project_root,
                "project_id": project_id,
                "source_root": source_root,
                "commit_sha": next(
                    (
                        str(result.metadata.get("commit_sha") or "")
                        for result in results.values()
                        if isinstance(result.metadata, dict)
                        and result.metadata.get("commit_sha")
                    ),
                    "",
                ),
                "audit_observation_count": len(unique_observations),
                "audit_observations": unique_observations,
                "report_view_summary": view_summary,
                "diff_relevance_summary": diff_relevance_summary,
                "diff_impact_coverage": diff_coverage,
                "context_tokens": total_context_tokens,
                "cumulative_prompt_tokens": (
                    response_prompt_tokens or retained_prompt_tokens
                ),
                "cumulative_completion_tokens": (
                    response_completion_tokens or retained_completion_tokens
                ),
                "cumulative_total_tokens": (
                    response_total_tokens or retained_total_tokens
                ),
                "retained_entry_prompt_tokens": retained_prompt_tokens,
                "retained_entry_completion_tokens": retained_completion_tokens,
                "retained_entry_total_tokens": retained_total_tokens,
                "llm_usage": llm_usage_summary,
                "validation_performance": validation_performance_summary,
                "global_validation_queue": {
                    "enabled": self._uses_scan_validation_queue(),
                    "duration_seconds": round(global_validation_duration, 4),
                    "unique_group_count": int(
                        global_validation_state.get("validation_group_count", 0) or 0
                    ),
                    "raw_occurrence_count": int(
                        global_validation_state.get("scan_level_raw_occurrence_count", 0) or 0
                    ),
                },
                "project_deterministic_fact_pass": project_fact_state,
                "va_candidate_coverage_summary": va_candidate_coverage_summary,
                "entry_budget": entry_budget_summary,
                "llm_iteration_budget": llm_iteration_budget_summary,
                "scan_budget": scan_budget_summary,
                "engine_capabilities": engine_capabilities,
                "semantic_dedup_summary": semantic_dedup_summary,
                "interrupted": interrupted,
            },
        }
        apply_report_schema_v2(
            combined_report,
            state={
                "interrupted": interrupted,
                "any_failure": error_result_count > 0,
                "candidate_terminal_states": unique_terminal_states,
                "engine_capabilities": engine_capabilities,
                "canonical_outcome_projection": canonical_projection,
                "candidate_ledger_summary": ledger_snapshot.get("summary", {}),
            },
            issues=unique_issues,
            observations=unique_observations,
            metadata=combined_report["metadata"],
            entry_function="__batch__",
        )
        
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(combined_report, f, indent=2, ensure_ascii=False)
            logger.info(f"Combined report saved to: {output_path}")
        
        return combined_report

    def _deferred_entry_terminal_states(
        self,
        project_id: str,
        project_root: str,
    ) -> List[Dict[str, Any]]:
        terminal: List[Dict[str, Any]] = []
        for candidate in getattr(self, "deferred_entry_candidates", []) or []:
            if not isinstance(candidate, dict):
                continue
            identity_payload = {
                "project": project_id,
                "function": candidate.get("function_name"),
                "file": FunctionEntry(
                    function_name=str(candidate.get("function_name") or ""),
                    file_path=str(candidate.get("file_path") or "") or None,
                ).normalized_file_path(Path(project_root)),
                "signature": candidate.get("signature"),
            }
            digest = hashlib.sha256(
                json.dumps(
                    identity_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()[:24]
            terminal.append(
                {
                    "candidate_schema_version": "zscope.entry-candidate.v1",
                    "candidate_uid": f"ENTRY_{digest}",
                    "candidate_disposition": "deferred_budget",
                    "status": "deferred_budget",
                    "deferred_reason": candidate.get("deferred_reason")
                    or "entry_discovery_budget",
                    "function": candidate.get("function_name"),
                    "file": candidate.get("file_path"),
                    "signature": candidate.get("signature"),
                    "exposure": candidate.get("exposure"),
                }
            )
        return terminal

    def _validation_performance_summary(
        self,
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, Any]:
        keys = (
            "iterations",
            "tool_call_count",
            "validator_fast_path_attempted",
            "validator_fast_path_accepted",
            "validator_cache_hit",
            "validator_inflight_coalesced",
            "validation_group_count",
            "validation_group_merged_count",
            "prevalidation_decision_count",
            "deterministic_prevalidation_decision_count",
            "deterministic_prevalidation_confirmed_count",
            "deterministic_prevalidation_rejected_count",
            "deterministic_prevalidation_conflict_count",
            "validator_avoided_count",
            "clang_prevalidation_decision_count",
            "static_audit_observation_count",
            "static_suppressed_count",
        )
        summary = {key: 0 for key in keys}
        for result in results.values():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            perf = metadata.get("validation_performance") if isinstance(metadata.get("validation_performance"), dict) else {}
            for key in keys:
                try:
                    summary[key] += int(perf.get(key, 0) or 0)
                except (TypeError, ValueError):
                    continue
        global_state = getattr(self, "_global_validation_state", {}) or {}
        for key in keys:
            try:
                summary[key] += int(global_state.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
        raw_occurrences = int(global_state.get("scan_level_raw_occurrence_count", 0) or 0)
        scan_groups = int(global_state.get("validation_group_count", 0) or 0)
        grouped_aliases = max(0, raw_occurrences - scan_groups)
        if grouped_aliases:
            summary["validation_group_merged_count"] += grouped_aliases
        summary["scan_level_raw_occurrence_count"] = raw_occurrences
        summary["scan_level_grouped_alias_count"] = grouped_aliases
        # The eligibility denominator intentionally includes only occurrences
        # already assigned to a canonical validation cluster.  Legacy records
        # without a structural identity remain visible but cannot be counted as
        # safely coalescible work.
        eligible_occurrences = int(
            global_state.get("eligible_alias_occurrence_count", raw_occurrences)
            or 0
        )
        eligible_groups = int(
            global_state.get("eligible_validation_group_count", scan_groups)
            or 0
        )
        eligible_aliases = max(0, eligible_occurrences - eligible_groups)
        summary["eligible_alias_occurrence_count"] = eligible_occurrences
        summary["eligible_validation_group_count"] = eligible_groups
        summary["eligible_coalescing_rate"] = (
            round(eligible_aliases / eligible_occurrences, 4)
            if eligible_occurrences
            else 1.0
        )
        summary["all_occurrence_reduction_rate"] = (
            round(grouped_aliases / raw_occurrences, 4)
            if raw_occurrences
            else 1.0
        )
        eligible_duplicate_requests = int(
            global_state.get("eligible_duplicate_request_count", 0) or 0
        )
        coalesced_duplicate_requests = int(
            global_state.get("coalesced_duplicate_request_count", 0) or 0
        )
        summary["eligible_duplicate_request_count"] = eligible_duplicate_requests
        summary["coalesced_duplicate_request_count"] = coalesced_duplicate_requests
        summary["coalescing_hit_rate"] = (
            round(coalesced_duplicate_requests / eligible_duplicate_requests, 4)
            if eligible_duplicate_requests
            else 1.0
        )
        summary["cluster_fragmentation_by_reason"] = dict(
            global_state.get("cluster_fragmentation_by_reason") or {}
        )
        summary["structural_coalescing_rate"] = (
            round(grouped_aliases / raw_occurrences, 4)
            if raw_occurrences
            else 1.0
        )
        eligible = int(summary.get("validation_group_merged_count") or 0)
        reused = int(summary.get("validator_cache_hit") or 0)
        summary["validation_reuse_rate"] = (
            round(min(1.0, reused / eligible), 4) if eligible else 1.0
        )
        return summary

    @staticmethod
    def _entry_budget_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, Any]:
        budgeted = [
            result
            for result in results.values()
            if result.entry_budget_seconds is not None
        ]
        exceeded = [
            result
            for result in budgeted
            if result.entry_budget_exceeded
        ]
        policies = sorted(
            {
                str(result.budget_exhaustion_policy or "observe")
                for result in results.values()
            }
        )
        return {
            "policy": policies[0] if len(policies) == 1 else "mixed",
            "measured_entry_count": len(results),
            "budgeted_entry_count": len(budgeted),
            "exceeded_entry_count": len(exceeded),
            "total_overrun_seconds": round(
                sum(result.entry_budget_overrun_seconds for result in exceeded),
                3,
            ),
            "max_overrun_seconds": round(
                max(
                    (
                        result.entry_budget_overrun_seconds
                        for result in exceeded
                    ),
                    default=0.0,
                ),
                3,
            ),
        }

    @staticmethod
    def _llm_iteration_budget_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, Any]:
        observations: List[Dict[str, Any]] = []
        exceeded_entries: set[str] = set()
        for entry_key, result in results.items():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            for raw in metadata.get("budget_observations", []) or []:
                if (
                    not isinstance(raw, dict)
                    or raw.get("kind") != "llm_iteration_budget"
                    or not raw.get("budget_reached")
                ):
                    continue
                item = dict(raw)
                item["entry_identity"] = result.entry_identity or entry_key
                observations.append(item)
                exceeded_entries.add(result.entry_identity or entry_key)
        return {
            "budget_reached_count": len(observations),
            "affected_entry_count": len(exceeded_entries),
            "hard_failure_count": sum(
                1 for item in observations if item.get("hard_failure")
            ),
            "observations": observations,
        }

    def _llm_usage_summary(self) -> Dict[str, Any]:
        """Aggregate response-boundary usage without losing cancelled entry work."""

        clients = getattr(self, "_shared_llm_clients", {}) or {}
        unique: Dict[int, Dict[str, Any]] = {}
        for ref, client in clients.items():
            client_id = id(client)
            row = unique.setdefault(
                client_id,
                {
                    "refs": [],
                    "client": client,
                },
            )
            row["refs"].append(str(ref))

        totals = {
            "successful_calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "estimated_calls": 0,
            "provider_reported_calls": 0,
        }
        per_client: List[Dict[str, Any]] = []
        for row in unique.values():
            snapshotter = getattr(row["client"], "usage_snapshot", None)
            if not callable(snapshotter):
                continue
            raw = snapshotter()
            snapshot = dict(raw) if isinstance(raw, dict) else {}
            for key in totals:
                totals[key] += int(snapshot.get(key) or 0)
            per_client.append(
                {
                    "llm_refs": sorted(set(row["refs"])),
                    **snapshot,
                }
            )

        successful_calls = totals["successful_calls"]
        totals["provider_usage_coverage"] = round(
            (
                totals["provider_reported_calls"] / successful_calls
                if successful_calls
                else 0.0
            ),
            4,
        )
        return {
            **totals,
            "accounting_scope": "successful_response_boundary",
            "failed_or_disconnected_request_usage": "unknown",
            "per_client": per_client,
        }

    @staticmethod
    def _va_candidate_coverage_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for result in results.values():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            coverage = metadata.get("va_candidate_coverage_summary")
            if not isinstance(coverage, dict):
                continue
            for key, value in coverage.items():
                try:
                    summary[key] = summary.get(key, 0) + int(value or 0)
                except (TypeError, ValueError):
                    continue
        return summary

    @classmethod
    def _annotate_diff_relevance(
        cls,
        issue: Dict[str, Any],
        diff_focus: Optional[Dict[str, Any]],
    ) -> None:
        if not isinstance(diff_focus, dict) or diff_focus.get("mode") != "diff_impact":
            return
        relevance = cls._classify_diff_relevance(issue, diff_focus)
        label = {
            "incremental": "[增量]",
            "existing": "[存量]",
            "unknown": "[影响待确认]",
        }.get(relevance, "[影响待确认]")
        issue["diff_relevance"] = relevance
        issue["diff_relevance_label"] = label
        issue["diff_focus"] = cls._compact_diff_focus_for_issue(diff_focus)
        cls._prefix_issue_summary(issue, label)

    @classmethod
    def _classify_diff_relevance(
        cls,
        issue: Dict[str, Any],
        diff_focus: Dict[str, Any],
    ) -> str:
        changed_functions = diff_focus.get("changed_functions")
        if not isinstance(changed_functions, list):
            return "unknown"
        changed_names = {
            str(item.get("function_name") or "")
            for item in changed_functions
            if isinstance(item, dict)
        }
        issue_func = str(issue.get("function") or issue.get("func_name") or "")
        issue_file, issue_line = parse_issue_location(str(issue.get("location") or ""))
        if issue_func:
            if issue_file:
                for item in changed_functions:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("function_name") or "") != issue_func:
                        continue
                    if cls._same_report_path(issue_file, str(item.get("file_path") or "")):
                        return "incremental"
            elif issue_func in changed_names:
                return "incremental"

        if issue_file and issue_line is not None:
            for item in changed_functions:
                if not isinstance(item, dict):
                    continue
                changed_file = str(item.get("file_path") or "")
                changed_lines = item.get("changed_lines")
                if not isinstance(changed_lines, list):
                    continue
                if cls._same_report_path(issue_file, changed_file) and issue_line in {
                    int(line) for line in changed_lines if str(line).isdigit()
                }:
                    return "incremental"

        affected_path_nodes = set()
        affected_path_pairs = set()
        saw_path_refs = False
        for path_item in diff_focus.get("affected_paths") or []:
            if not isinstance(path_item, dict):
                continue
            path = path_item.get("path")
            if isinstance(path, list):
                affected_path_nodes.update(str(node) for node in path if str(node))
            for ref in path_item.get("path_refs") or []:
                if not isinstance(ref, dict):
                    continue
                saw_path_refs = True
                ref_name = str(ref.get("function_name") or "")
                ref_file = str(ref.get("file_path") or "")
                if ref_name and ref_file:
                    affected_path_pairs.add((ref_name, ref_file))
        if issue_func and issue_file and affected_path_pairs:
            if any(
                name == issue_func and cls._same_report_path(issue_file, file_path)
                for name, file_path in affected_path_pairs
            ):
                return "incremental"
        elif issue_func and issue_func in affected_path_nodes and (not issue_file or not saw_path_refs):
            return "incremental"
        if diff_focus.get("fallback_reasons"):
            return "unknown"
        return "existing"

    @staticmethod
    def _same_report_path(left: str, right: str) -> bool:
        left_norm = str(left or "").replace("\\", "/").lstrip("./")
        right_norm = str(right or "").replace("\\", "/").lstrip("./")
        return bool(
            left_norm
            and right_norm
            and (left_norm == right_norm or left_norm.endswith("/" + right_norm) or right_norm.endswith("/" + left_norm))
        )

    @staticmethod
    def _compact_diff_focus_for_issue(diff_focus: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "component": diff_focus.get("component", ""),
            "base_ref": diff_focus.get("base_ref", ""),
            "head_ref": diff_focus.get("head_ref", ""),
            "entry_function": diff_focus.get("entry_function", ""),
            "entry_exposure": diff_focus.get("entry_exposure", ""),
            "fallback_reasons": list(diff_focus.get("fallback_reasons") or []),
            "changed_functions": [
                {
                    "function_name": item.get("function_name", ""),
                    "file_path": item.get("file_path", ""),
                    "changed_lines": list(item.get("changed_lines") or []),
                }
                for item in diff_focus.get("changed_functions") or []
                if isinstance(item, dict)
            ],
        }

    @staticmethod
    def _prefix_issue_summary(issue: Dict[str, Any], label: str) -> None:
        for key in ("title", "summary", "description"):
            value = issue.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            if value.startswith("[增量]") or value.startswith("[存量]") or value.startswith("[影响待确认]"):
                return
            issue[key] = f"{label} {value}"
            return
        issue["summary"] = label

    @staticmethod
    def _diff_relevance_summary(
        issues: List[Dict[str, Any]],
        observations: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, int]]:
        def count(items: List[Dict[str, Any]]) -> Dict[str, int]:
            result = {"incremental": 0, "existing": 0, "unknown": 0, "unscoped": 0}
            for item in items:
                relevance = str(item.get("diff_relevance") or "unscoped")
                if relevance not in result:
                    relevance = "unknown"
                result[relevance] += 1
            return result

        return {"issues": count(issues), "audit_observations": count(observations)}

    def _diff_coverage_metadata(self) -> Dict[str, Any]:
        if not hasattr(self, "base_config"):
            return {}
        project = getattr(self.base_config, "project", None)
        entry_list = getattr(project, "entry_functions_list", None)
        if not entry_list:
            return {}
        path = Path(entry_list)
        if not path.exists() or not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("Unable to read diff coverage metadata from %s: %s", path, exc)
            return {}
        diff_impact = data.get("diff_impact") if isinstance(data, dict) else None
        if not isinstance(diff_impact, dict):
            return {}
        return {
            "coverage_summary": diff_impact.get("coverage_summary") or {},
            "function_coverage": diff_impact.get("function_coverage") or [],
            "analysis_obligations": diff_impact.get("analysis_obligations") or [],
        }

    def generate_combined_markdown_report(
        self, 
        results: Dict[str, ParallelAnalysisResult], 
        output_path: Path
    ) -> str:
        """
        Generate a human-readable Markdown report for batch analysis.
        
        Args:
            results: Dict of function name to analysis result
            output_path: Path to save combined report
            
        Returns:
            Markdown report content
        """
        summary = {
            "total": len(results),
            "issues_found": sum(1 for r in results.values() if r.verdict == "issues_found"),
            "no_issue": sum(1 for r in results.values() if r.verdict == "no_issue_found"),
            "error": sum(1 for r in results.values() if r.verdict == "error"),
            "total_issues": sum(len(r.issues) for r in results.values()),
            "audit_observations": sum(len(r.audit_observations) for r in results.values()),
            "deferred_entries": len(
                getattr(self, "deferred_entry_candidates", []) or []
            ),
        }
        incomplete = bool(summary["error"] or summary["deferred_entries"]) or any(
            str(item.get("candidate_disposition") or "").lower()
            in {"deferred_budget", "engine_failed"}
            for result in results.values()
            for item in result.candidate_terminal_states
            if isinstance(item, dict)
        )
        
        md = [
            "# Z-SCOPE Batch Analysis Report",
            "",
            "## Summary",
            f"- **Completeness**: {'incomplete' if incomplete else 'complete'}",
            f"- **Functions Analyzed**: {summary['total']}",
            f"- **Issues Found**: {summary['issues_found']}",
            f"- **No Issues Found**: {summary['no_issue']}",
            f"- **Errors**: {summary['error']}",
            f"- **Total Issues Detected**: {summary['total_issues']}",
            f"- **Audit Observations**: {summary['audit_observations']}",
            f"- **Deferred Entry Candidates**: {summary['deferred_entries']}",
        ]

        diff_coverage = self._diff_coverage_metadata()
        coverage_summary = diff_coverage.get("coverage_summary") if isinstance(diff_coverage, dict) else {}
        if isinstance(coverage_summary, dict) and coverage_summary:
            md.extend(
                [
                    "",
                    "## Diff Impact Coverage",
                    f"- **Changed Functions**: {coverage_summary.get('changed_total', 0)}",
                    f"- **Scan Entries**: {coverage_summary.get('scan_entry_count', 0)}",
                    f"- **Covered By Scan**: {coverage_summary.get('covered_by_scan', 0)}",
                    f"- **Context Only**: {coverage_summary.get('context_only', 0)}",
                    f"- **Triage Only**: {coverage_summary.get('triage_only', 0)}",
                    f"- **Unresolved**: {coverage_summary.get('unresolved', 0)}",
                ]
            )
            not_root = [
                item
                for item in diff_coverage.get("function_coverage", [])
                if isinstance(item, dict)
                and str(item.get("coverage_status") or "") != "scanned_as_root"
            ]
            if not_root:
                md.extend(
                    [
                        "",
                        "| Function | Coverage | Scan Entry | Reason |",
                        "| :--- | :--- | :--- | :--- |",
                    ]
                )
                for item in not_root[:20]:
                    md.append(
                        "| "
                        f"`{item.get('function_name', '')}` | "
                        f"{item.get('coverage_status', '')} | "
                        f"`{item.get('scan_entry', '')}` | "
                        f"{item.get('reason', '')} |"
                    )
                if len(not_root) > 20:
                    md.append(f"| ... | ... | ... | +{len(not_root) - 20} more |")

        md.extend(
            [
                "",
                "## Function Details",
                "",
                "| Function | Verdict | Issues | Needs Review / Audit | Duration |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        
        for name, res in sorted(results.items()):
            duration_str = f"{res.duration_seconds:.1f}s" if res.duration_seconds else "N/A"
            display_name = res.function_name if name == res.function_name else f"{res.function_name} ({name})"
            needs_review_count = sum(
                1
                for issue in res.audit_observations
                if str(issue.get("validation_status") or "").lower() == "needs_review"
            )
            md.append(
                f"| {display_name} | {res.verdict} | {len(res.issues)} | "
                f"{needs_review_count} / {len(res.audit_observations)} | {duration_str} |"
            )
        
        md.append("")
        md.append("## Detected Issues")
        md.append("")
        
        # Group issues by analyzed_from (entry function)
        issues_by_entry = {}
        for entry_key, r in results.items():
            if r.verdict == "issues_found":
                issues_by_entry[entry_key] = r.issues

        if not issues_by_entry:
            md.append("*No issues detected.*")
        else:
            for entry_func, issues in sorted(issues_by_entry.items()):
                md.append(f"### Entry Function: `{entry_func}`")
                md.append("")
                
                # Simple deduplication per entry if needed
                seen_in_entry = set()
                
                for idx, issue in enumerate(issues, 1):
                    # Skip rejected issues in offline markdown report
                    if issue.get("validation_status") == "rejected":
                        continue
                    
                    issue_key = f"{issue.get('location', 'N/A')}:{issue.get('description', '')[:50]}"
                    if issue_key in seen_in_entry:
                        continue
                    seen_in_entry.add(issue_key)
                    
                    impact = str(issue.get("impact_level", "UNKNOWN")).upper()
                    conf = issue.get("confidence", "N/A")
                    if isinstance(conf, float):
                        conf = f"{conf:.2f}"
                        
                    snippet = issue.get("code_snippet")
                    md.extend([
                        f"#### {idx}. [{impact}] {issue.get('id', f'ISSUE_{idx}')}: {issue.get('function', 'N/A')}",
                        f"- **Location**: `{issue.get('location', 'N/A')}`",
                        f"- **Confidence**: `{conf}`",
                        f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                    ])
                    if snippet:
                        md.append(f"- **Relevant Code**:\n```c\n{self._normalize_md_text(snippet)}\n```")
                    
                    md.append(f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}")
                    
                    # Add reasoning if present
                    reasoning = issue.get('reasoning')
                    if reasoning:
                        md.append(f"- **Analysis Reasoning**: {self._normalize_md_text(reasoning)}")
                    
                    md.append(f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}")
                    md.append(f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}")
                    
                    # Add validation status and reasoning
                    val_status = issue.get('validation_status')
                    if val_status:
                        status_emoji = {"validated": "✅", "rejected": "❌", "pending": "⏳", "unvalidated": "⚠️"}.get(val_status, "")
                        md.append(f"- **Validation Status**: {status_emoji} {val_status}")
                        
                        val_reasoning = issue.get('validation_reasoning')
                        if val_reasoning:
                            md.append(f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}")
                    
                    md.append("")

        needs_review_by_entry = {}
        for entry_key, r in results.items():
            review_items = [
                issue
                for issue in r.audit_observations
                if str(issue.get("validation_status") or "").lower() == "needs_review"
            ]
            if review_items:
                needs_review_by_entry[entry_key] = review_items

        md.append("")
        md.append("## Needs Review Findings")
        md.append("")
        if not needs_review_by_entry:
            md.append("*No needs_review observations.*")
        else:
            for entry_func, issues in sorted(needs_review_by_entry.items()):
                md.append(f"### Entry Function: `{entry_func}`")
                md.append("")
                for idx, issue in enumerate(issues, 1):
                    impact = str(issue.get("impact_level", "UNKNOWN")).upper()
                    conf = issue.get("confidence", "N/A")
                    if isinstance(conf, float):
                        conf = f"{conf:.2f}"
                    md.extend([
                        f"#### {idx}. [{impact}] {issue.get('id', f'REVIEW_{idx}')}: {issue.get('function', 'N/A')}",
                        f"- **Location**: `{issue.get('location', 'N/A')}`",
                        f"- **Confidence**: `{conf}`",
                        f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                        f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}",
                        f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}",
                        f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}",
                    ])
                    val_reasoning = issue.get("validation_reasoning")
                    if val_reasoning:
                        md.append(f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}")
                    md.append("")
                
        content = "\n".join(md)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        logger.info(f"Markdown report saved to: {output_path}")
        return content

    
    def _deduplicate_issues(self, issues: List[Dict]) -> List[Dict]:
        """Remove duplicate issues based on canonical sink/root-cause evidence."""
        semantic_cfg = getattr(getattr(getattr(self, "base_config", None), "reporting", None), "semantic_dedup", None)
        if semantic_cfg is not None and getattr(semantic_cfg, "enabled", True):
            deduped, _summary = deduplicate_semantic_issues_programmatic(issues)
            return deduped
        return deduplicate_issues(issues)

    def _deduplicate_report_issues(
        self,
        issues: List[Dict[str, Any]],
        *,
        allow_llm: bool = True,
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Apply batch final-report semantic dedup, including LLM dedup when enabled."""
        semantic_cfg = getattr(getattr(getattr(self, "base_config", None), "reporting", None), "semantic_dedup", None)
        if semantic_cfg is None or not getattr(semantic_cfg, "enabled", True):
            deduped = deduplicate_issues(issues)
            return deduped, {
                "enabled": False,
                "input_issue_count": len(issues),
                "output_issue_count": len(deduped),
            }

        deduped, summary = deduplicate_semantic_issues_programmatic(issues)
        llm_configured = bool(getattr(semantic_cfg, "llm_enabled", False))
        llm_enabled = bool(llm_configured and allow_llm)
        summary.update(
            {
                "enabled": True,
                "llm_enabled": llm_enabled,
                "llm_configured": llm_configured,
                "input_issue_count": len(issues),
                "after_programmatic_issue_count": len(deduped),
            }
        )
        if llm_configured and not allow_llm:
            summary["llm_disabled_reason"] = "interrupted_fast_shutdown"
        if llm_enabled:
            deduped, llm_summary = self._deduplicate_report_clusters_with_llm(
                deduped,
                semantic_cfg=semantic_cfg,
            )
            summary.update(llm_summary)
        summary["output_issue_count"] = len(deduped)
        return deduped, summary

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
            "llm_suggestion_count": 0,
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

        self._assign_semantic_dedup_ids(issues)
        by_issue_id: Dict[str, Dict[str, Any]] = {}
        issue_order: List[str] = []
        issue_indices = {id(issue): index for index, issue in enumerate(issues)}
        for index, issue in enumerate(issues):
            issue_id = self._semantic_dedup_issue_id(issue, index)
            by_issue_id[issue_id] = issue
            issue_order.append(issue_id)

        cache = getattr(self, "_semantic_dedup_llm_cache", None)
        if cache is None:
            cache = {}
            self._semantic_dedup_llm_cache = cache

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
            decision = cache.get(cluster_fingerprint)
            if decision is not None:
                summary["llm_cache_hits"] += 1
            else:
                response = recon_agent.run(cluster_payload)
                summary["llm_clusters_called"] += 1
                if not response.success or not isinstance(response.data, dict):
                    summary["llm_failed_cluster_count"] += 1
                    continue
                decision = response.data
                cache[cluster_fingerprint] = decision

            suggested, rejected = self._apply_llm_dedup_decision(
                decision,
                by_issue_id,
                removed,
                threshold=threshold,
            )
            summary["llm_suggestion_count"] += suggested
            summary["llm_rejected_merge_count"] += rejected

        result = [issue for issue_id, issue in zip(issue_order, issues) if issue_id not in removed]
        for issue in issues:
            issue.pop("_semantic_dedup_uid", None)
        return result, summary

    @staticmethod
    def _semantic_dedup_cluster_needs_llm(group: List[Dict[str, Any]]) -> bool:
        for left_index, left in enumerate(group):
            for right in group[left_index + 1 :]:
                if not ParallelAnalyzer._semantic_dedup_pair_needs_llm(left, right):
                    continue
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
        config = getattr(self, "base_config", None)
        agents = getattr(getattr(config, "project", None), "agents", []) if config is not None else []
        recon_agent_cfg = next(
            (agent for agent in agents if getattr(agent, "name", "") == "issue_reconciler_agent"),
            None,
        )
        recon_llm_ref = getattr(recon_agent_cfg, "llm_ref", "") if recon_agent_cfg else ""
        recon_llm_ref = recon_llm_ref or "default"
        clients = getattr(self, "_shared_llm_clients", {}) or {}
        recon_client = clients.get(recon_llm_ref) or clients.get("default")
        if recon_client is None:
            logger.warning("Batch semantic LLM dedup requested but no issue_reconciler_agent LLM client is configured.")
            return None

        from ..agents.issue_reconciler.agent import IssueReconcilerAgent

        return IssueReconcilerAgent(recon_client)

    @staticmethod
    def _semantic_dedup_issue_id(issue: Dict[str, Any], index: int) -> str:
        return str(
            issue.get("_semantic_dedup_uid")
            or issue.get("run_issue_uid")
            or issue.get("occurrence_uid")
            or issue.get("candidate_uid")
            or issue.get("candidate_id")
            or issue.get("dedup_key")
            or f"semantic_issue_{index}"
        )

    @staticmethod
    def _assign_semantic_dedup_ids(issues: List[Dict[str, Any]]) -> None:
        bases = []
        for index, issue in enumerate(issues):
            internal = (
                issue.get("run_issue_uid")
                or issue.get("occurrence_uid")
                or issue.get("candidate_uid")
                or issue.get("candidate_id")
                or issue.get("dedup_key")
            )
            if not internal:
                payload = {
                    "canonical": canonical_issue_key(issue),
                    "evidence_hash": issue.get("evidence_hash"),
                    "index": index,
                }
                internal = "SEM_" + hashlib.sha256(
                    json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
                ).hexdigest()[:24]
            bases.append(str(internal))
        counts = {base: bases.count(base) for base in set(bases)}
        for index, (issue, base) in enumerate(zip(issues, bases)):
            if counts[base] == 1:
                issue["_semantic_dedup_uid"] = base
                continue
            issue["_semantic_dedup_uid"] = str(
                issue.get("run_issue_uid")
                or issue.get("occurrence_uid")
                or f"{base}::{index}"
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
                structurally_equivalent = issues_may_share_root_cause(
                    primary,
                    duplicate,
                    confidence=confidence,
                    threshold=threshold,
                    allow_cross_function_root=True,
                )
                primary_cluster = str(primary.get("validation_cluster_uid") or "")
                duplicate_cluster = str(duplicate.get("validation_cluster_uid") or "")
                structurally_blocked = bool(
                    primary_cluster
                    and duplicate_cluster
                    and primary_cluster != duplicate_cluster
                )
                if not structurally_equivalent and not structurally_blocked:
                    rejected += 1
                    continue
                root_key = str(group.get("root_cause_key") or "") or semantic_root_cause_key(primary)
                suggestion = {
                    "method": "issue_reconciler_agent_suggestion",
                    "root_cause_key": root_key,
                    "confidence": confidence,
                    "reasoning": group.get("reasoning"),
                    # A model may describe a possible relationship, but a
                    # distinct structured decision identity is an explicit
                    # no-merge boundary.  Preserve the suggestion for audit
                    # without allowing it to remove either finding.
                    "structural_merge_blocked": structurally_blocked,
                }
                primary.setdefault("dedup_cluster_suggestions", []).append(
                    {**suggestion, "role": "primary", "peer_issue_uid": duplicate_id}
                )
                duplicate.setdefault("dedup_cluster_suggestions", []).append(
                    {**suggestion, "role": "possible_alias", "peer_issue_uid": primary_id}
                )
                applied += 1
        return applied, rejected

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
    
    def _group_by_severity(self, issues: List[Dict]) -> Dict[str, List[Dict]]:
        """Group issues by impact level."""
        groups: Dict[str, List[Dict[str, Any]]] = {"critical": [], "high": [], "medium": [], "low": []}
        
        for issue in issues:
            level = issue.get("impact_level", "medium").lower()
            if level in groups:
                groups[level].append(issue)
            else:
                groups["medium"].append(issue)
        
        return groups
