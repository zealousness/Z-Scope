"""
Parallel Analyzer for Z-SCOPE.
Supports concurrent analysis of multiple functions using thread pool.
"""

import concurrent.futures
import hashlib
import json
import logging
import re
import tempfile
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
from ..framework.llm_usage import (
    ensure_scan_token_usage_ledger,
    scan_token_usage_snapshot,
)
from ..semantics.inference import LocalPatternSemanticBuilder
from ..semantics.models import LocalPatternSemantics
from ..semantics.security_map import SQLiteSecurityMapStore, ZeroLLMSecurityMapBuilder
from ..semantics.security_specs.shadow import SecuritySpecShadowRuntime
from ..semantics.security_specs.store import SecuritySpecStore
from ..semantics.security_specs.qualification import load_builtin_qualification
from ..semantics.security_specs.manifest import load_shadow_manifest_identity
from ..snapshots.store import SnapshotStore
from ..retrieval.code_index import CodeIndex
from ..orchestration.active_discovery import (
    ActiveDiscoveryAgent,
    ActiveDiscoveryCoordinator,
    SemanticEnrichmentAgent,
    SemanticMapEnricher,
    candidate_coverage_keys,
    historical_variant_keys,
    make_agent_report_runner,
    make_semantic_enrichment_runner,
    resolve_discovery_profile,
)
from ..orchestration.candidates import CandidateLedger, CandidateRegistrar
from ..orchestration.decision_trace import DecisionTraceStore, ensure_decision_trace_store
from ..orchestration.candidate_envelope import annotate_issue_identity
from ..orchestration.global_modeler import GlobalModeler
from ..orchestration.rollout import (
    rollout_active_discovery_mode,
    rollout_runtime_policy,
)
from ..orchestration.scheduler import ENTRY_ROLE, ScanScheduler
from ..common.issue_identity import (
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
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
    report_view_summary,
)
from ..reporting.schema import apply_report_schema_v2, coalesce_terminal_candidates
from ..reporting.assembler import ReportAssembler
from ..rules.extensions import preflight_rules
from ..rules.catalog import serialize_effective_rules
from ..benchmarking.discovery_ablation import (
    DiscoveryAblationError,
    DiscoveryAblationRuntimeOverride,
)

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

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: Optional[CodeIndex] = None,
        user_config: Optional[UserConfigStore] = None,
        force_ignore_history: bool = False,
        maintain_mode: bool = False,
        cancellation_token: Optional[CancellationToken] = None,
        benchmark_ablation_override: Optional[DiscoveryAblationRuntimeOverride] = None,
    ):
        preflight_rules(config)
        self.base_config = config
        self.max_workers = config.concurrency.entry_workers
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        self._benchmark_ablation_override = benchmark_ablation_override
        if benchmark_ablation_override is not None:
            benchmark_ablation_override.require_in_process_supported()
            benchmark_ablation_override.validate_runtime_config(config)
            benchmark_ablation_override.require_cold_runtime_attested()
            if not force_ignore_history or maintain_mode:
                raise DiscoveryAblationError(
                    "isolated-cold ablation requires ignored history and forbids maintain mode"
                )
        self._shared_llm_clients = self._build_shared_llm_clients(config)
        self._validation_result_cache = ValidationResultCache(
            max_entries=getattr(config.analysis, "validation_cache_entries", 4096)
        )
        self._decision_fact_cache = DecisionFactGraphCache()
        self._decision_trace_store = ensure_decision_trace_store(config)
        self._candidate_ledger = CandidateLedger(
            project_id=str(
                getattr(config.project, "project_id", "") or config.project.project_root.name
            ),
            project_root=str(config.project.project_root),
            revision=Analyzer._git_commit_sha(config.project.project_root),
            decision_trace_store=self._decision_trace_store,
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
                svf_parallel_workers=(
                    config.concurrency.svf_workers or config.concurrency.index_workers
                ),
            )
        self.snapshot_store = SnapshotStore.from_config(config)
        db_dir = (
            Path(config.analysis.user_config_db)
            if config.analysis.user_config_db
            else Path(config.analysis.snapshot_dir)
        )
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
        self._last_materialized_entries: List[FunctionEntry] = []
        self._last_batch_wall_seconds = 0.0
        self._last_scan_budget_metadata: Dict[str, Any] = {}
        self._last_global_model_stats: Optional[Dict[str, Any]] = None
        self._global_modeling_succeeded = False
        self._global_validation_state: Dict[str, Any] = {}
        self._global_validation_duration_seconds = 0.0
        self._project_fact_pass_state: Dict[str, Any] = {}
        self._active_discovery_state: Dict[str, Any] = {
            "enabled": False,
            "profile": resolve_discovery_profile(config).name,
            "status": "not_run",
        }
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
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
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
        self._last_materialized_entries = list(entries)
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
            revision=Analyzer._git_commit_sha(self.base_config.project.project_root),
            decision_trace_store=self._decision_trace_store,
        )
        self._decision_fact_cache = DecisionFactGraphCache()
        self._global_validation_state = {}
        self._global_validation_duration_seconds = 0.0
        self._project_fact_pass_state = {}
        self._active_discovery_state = {
            "enabled": False,
            "profile": resolve_discovery_profile(self.base_config).name,
            "status": "not_run",
        }
        self._cancellation_token.raise_if_cancelled()
        scheduler = ScanScheduler(
            entry_workers=self.max_workers,
            validator_workers=self.base_config.concurrency.validator_workers,
            investigator_workers=self.base_config.concurrency.investigator_workers,
        )
        self._scheduler = scheduler

        logger.info(
            f"Starting parallel analysis of {total} function entries with {self.max_workers} workers"
        )
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
                        logger.info(
                            f"[{completed}/{total}] {entry.function_name}: {result.verdict} ({len(result.issues)} issues, ctx ≈ {result.context_tokens:,} tokens)"
                        )
                    except concurrent.futures.CancelledError:
                        logger.warning(
                            f"[{completed}/{total}] {entry.function_name}: Cancelled due to interrupt"
                        )
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

            discovery_profile = resolve_discovery_profile(self.base_config)
            discovery_mode = rollout_active_discovery_mode(self.base_config)
            ablation_override = self._benchmark_ablation_override
            ablation_disables_map = bool(
                ablation_override is not None and not ablation_override.semantic_map_enabled
            )
            if (
                discovery_profile.name == "fast"
                or (discovery_mode == "disabled" and ablation_override is None)
                or ablation_disables_map
            ):
                # Fast is a true zero-work path: no semantic-map traversal,
                # sidecar writes, or discovery-model invocation.
                self._active_discovery_state = {
                    "enabled": False,
                    "profile": discovery_profile.name,
                    "status": (
                        "disabled_by_profile"
                        if discovery_profile.name == "fast"
                        else (
                            "disabled_by_ablation"
                            if ablation_disables_map
                            else "disabled_by_rollout"
                        )
                    ),
                    "visibility_mode": discovery_mode,
                    "rollout": rollout_runtime_policy(self.base_config),
                    "llm_semantic_model_calls": 0,
                    "llm_discovery_call_count": 0,
                }
                if ablation_override is not None:
                    self._active_discovery_state["benchmark_ablation"] = (
                        ablation_override.report_metadata()
                    )
                spec_identity = load_shadow_manifest_identity(
                    Path(self.base_config.analysis.snapshot_dir) / "security_specs",
                    consumer="scan",
                )
                self._active_discovery_state["security_spec_shadow"] = {
                    "schema_version": "zscope.security-spec-shadow-result.v2",
                    "security_spec_mode": spec_identity["security_spec_mode"],
                    "active_product_effect": "none",
                    "status": "replayed_read_only",
                    "root_manifest_sha256": spec_identity["security_spec_root_manifest_sha256"],
                    "artifact_refs": spec_identity["security_spec_artifact_refs"],
                    "compiled_spec_count": spec_identity["security_spec_shadow_decision"][
                        "compiled_spec_count"
                    ],
                    "reason_code": spec_identity["security_spec_shadow_decision"]["reason_code"],
                }
                self._decision_trace_store.update_identity(spec_identity)
            else:
                self._run_active_discovery(entries, discovery_profile)

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
                    "Scan budget exceeded: budget=%.2fs overrun=%.2fs " "policy=%s outcome=%s",
                    float(str(scan_budget_seconds)),
                    self._last_scan_budget_metadata["scan_budget_overrun_seconds"],
                    budget_exhaustion_policy,
                    ("completed"),
                )
            # Under normal successful execution, properly wait and clean up resources
            if scheduler and not (
                getattr(self, "_interrupted", False) or getattr(self, "_deadline_exceeded", False)
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
        return True

    def _run_scan_validation_queue(self) -> None:
        """Validate each frozen v3 obligation once after all entries discover it.

        Entry workers can discover the same local sink through many wrappers.
        The shared ledger has already merged those occurrences by
        ``validation_cluster_uid``.  Validating inside each entry therefore
        spends LLM calls before that merge can have any effect.  This method
        restores the intended lifecycle: discovery -> ledger -> one global
        validation queue -> final report projection.
        """

        # Active discovery is the final producer.  Seal the ledger before
        # taking the validation snapshot so no late producer can create an
        # obligation after queue construction has begun.
        self._candidate_ledger.freeze()

        pending: List[Dict[str, Any]] = []
        for record in self._candidate_ledger.records():
            if record.record_role != "validation_obligation" or record.disposition:
                continue
            evidence = deepcopy(
                record.ticket.evidence if isinstance(record.ticket.evidence, dict) else {}
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
                    "occurrence_uid": (record.occurrence_uids[0] if record.occurrence_uids else ""),
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
                "validation_queue_drained": True,
                "budget_exhaustion_policy": str(
                    getattr(self.base_config.analysis, "budget_exhaustion_policy", "observe")
                    or "observe"
                ),
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
        raw_occurrence_count = sum(len(record.occurrence_uids) for record in ledger_records)
        eligible_records = [
            record
            for record in ledger_records
            if str(record.decision_context_version or "").endswith(("v3.1", "v3.2", "v3.3"))
            and record.record_role == "validation_obligation"
        ]
        eligible_occurrence_count = sum(len(record.occurrence_uids) for record in eligible_records)
        eligible_duplicate_request_count = sum(
            max(0, len(record.occurrence_uids) - 1) for record in eligible_records
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
            "budget_exhaustion_policy": str(
                getattr(self.base_config.analysis, "budget_exhaustion_policy", "observe")
                or "observe"
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
        }
        started = time.monotonic()
        logger.info(
            "[validation-queue] start unique_groups=%d raw_occurrences=%d",
            len(pending),
            raw_occurrence_count,
        )
        self._bind_ablation_validator_policy(helper.validation_runner)
        helper.validation_runner.run(state)
        state.update(self._validator_v3_outcome_summary(pending))
        self._global_validation_duration_seconds = max(0.0, time.monotonic() - started)
        self._global_validation_state = state
        logger.info(
            "[validation-queue] end unique_groups=%d confirmed=%d review=%d duration=%.2fs",
            len(pending),
            len(state["issues"]),
            len(state["observations"]),
            self._global_validation_duration_seconds,
        )

    def _bind_ablation_validator_policy(self, runner: Any) -> None:
        """Make the frozen winning Validator arm control the live queue."""

        override = self._benchmark_ablation_override
        if override is None or override.validator_selected_arm == "D":
            return
        if override.validator_selected_arm == "C":
            # Arm C keeps V1+V2 but cannot inherit balanced's V3 investigation.
            setattr(runner, "_assign_v3_investigation_budget", lambda prepared: prepared)
            return
        if override.validator_selected_arm == "B":
            # Arm B is the direct structured decision arm: no fact recheck or V3.
            setattr(
                runner,
                "_run_v3_evidence_recheck",
                lambda _item, _agent, val_data, _metadata: val_data,
            )
            setattr(runner, "_assign_v3_investigation_budget", lambda prepared: prepared)
            return
        raise DiscoveryAblationError(
            f"unsupported live ablation Validator arm: {override.validator_selected_arm}"
        )

    @staticmethod
    def _validator_v3_outcome_summary(issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate auditable fact-resolution and verdict transitions."""

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

    @staticmethod
    def _scan_budget_metadata(
        *,
        duration_seconds: float,
        budget_seconds: Optional[float],
        policy: str,
    ) -> Dict[str, Any]:
        try:
            normalized_budget = float(budget_seconds) if budget_seconds is not None else None
        except (TypeError, ValueError):
            normalized_budget = None
        if normalized_budget is not None and normalized_budget <= 0:
            normalized_budget = None
        duration = max(0.0, float(duration_seconds or 0.0))
        exceeded = normalized_budget is not None and duration > normalized_budget
        overrun = max(0.0, duration - normalized_budget) if normalized_budget is not None else 0.0
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
            "rule_candidate_counts": {"by_engine": {}, "by_rule": {}, "total": 0},
            "unresolved_internal_functions": 0,
            "failures": [],
        }
        generator = ClangAstCfgCandidateGenerator(
            self._get_shared_local_pattern_semantics(),
            semantic_overlay=self._get_shared_semantic_overlay(),
            tooling_evidence_provider=None,
            rule_policy=self.base_config.effective_rules.policy,
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
                    callee.get("name") or callee.get("function") or callee.get("callee") or ""
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
                    emitted = helper._annotate_candidate_issues(
                        emitted,
                        checker=helper._local_candidate_checker(),
                        path_kind="project_deterministic_fact_pass",
                    )
                if emitted:
                    project_rule_counts = state["rule_candidate_counts"]
                    for issue in emitted:
                        if str(issue.get("candidate_kind") or "") != "deterministic_rule":
                            continue
                        rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
                        engine = str(issue.get("rule_engine") or "")
                        if rule_id:
                            by_rule = project_rule_counts["by_rule"]
                            by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
                        if engine:
                            by_engine = project_rule_counts["by_engine"]
                            by_engine[engine] = by_engine.get(engine, 0) + 1
                        project_rule_counts["total"] += 1
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

    def _run_active_discovery(self, entries: List[FunctionEntry], profile: Any) -> None:
        """Build the zero-LLM map and route bounded hypotheses into the ledger.

        This stage is best-effort by design.  A map/backend/model failure is
        reported as explicit coverage telemetry and never prevents already
        discovered obligations from reaching the shared Validator queue.
        """

        started = time.monotonic()
        snapshot_dir = Path(self.base_config.analysis.snapshot_dir)
        sidecar_path = snapshot_dir / "security_map.db"
        export_path = snapshot_dir / "security_semantic_map.json"
        state: Dict[str, Any] = {
            "enabled": True,
            "profile": str(profile.name),
            "status": "running",
            "sidecar_path": str(sidecar_path),
            "json_export_path": str(export_path),
            "llm_semantic_model_calls": 0,
            "llm_discovery_call_count": 0,
        }
        self._active_discovery_state = state
        try:
            ablation_override = self._benchmark_ablation_override
            discovery_enabled = bool(
                ablation_override is None or ablation_override.active_discovery_enabled
            )
            semantic_enrichment_enabled = bool(
                ablation_override is None or ablation_override.semantic_enrichment_enabled
            )
            if ablation_override is not None:
                state["benchmark_ablation"] = ablation_override.report_metadata()
            self._cancellation_token.raise_if_cancelled()
            max_functions_default = 15_000 if profile.name == "deep" else 5_000
            max_functions = int(
                getattr(
                    self.base_config.analysis,
                    "security_map_max_functions",
                    max_functions_default,
                )
                or max_functions_default
            )
            semantic_map = ZeroLLMSecurityMapBuilder(
                self.code_index,
                project_id=str(
                    getattr(self.base_config.project, "project_id", "")
                    or self.base_config.project.project_root.name
                ),
                revision=str(self._candidate_ledger.revision or ""),
                profile=str(profile.name),
                semantic_overlay=self._get_shared_semantic_overlay(),
                project_root=self.base_config.project.project_root,
                max_functions=max_functions,
            ).build(entries)
            self._cancellation_token.raise_if_cancelled()
            store = SQLiteSecurityMapStore(sidecar_path)
            registrar = CandidateRegistrar(
                self._candidate_ledger,
                project_id=str(
                    getattr(self.base_config.project, "project_id", "")
                    or self.base_config.project.project_root.name
                ),
                project_root=str(self.base_config.project.project_root),
                revision=str(self._candidate_ledger.revision or ""),
                run_id=self.run_id,
                decision_fact_cache=self._decision_fact_cache,
            )
            discovery_llm_client = (
                self._scan_role_llm_client("analysis") if discovery_enabled else None
            )
            modeling_llm_client = (
                self._scan_role_llm_client("modeling") if semantic_enrichment_enabled else None
            )
            report_runner = None
            semantic_enricher = None
            if discovery_llm_client is not None:
                agent_runner = make_agent_report_runner(ActiveDiscoveryAgent(discovery_llm_client))

                def report_runner(projection: Any, active_profile: Any) -> Any:
                    self._cancellation_token.raise_if_cancelled()
                    return agent_runner(projection, active_profile)

            if modeling_llm_client is not None:
                enrichment_runner = make_semantic_enrichment_runner(
                    SemanticEnrichmentAgent(modeling_llm_client)
                )

                def semantic_delta_runner(projection: Any, active_profile: Any) -> Any:
                    self._cancellation_token.raise_if_cancelled()
                    return enrichment_runner(projection, active_profile)

                semantic_enricher = SemanticMapEnricher(
                    profile=profile,
                    store=store,
                    model_identity=str(
                        (getattr(modeling_llm_client, "models", None) or ["unknown"])[0]
                    ),
                    user_semantics_fingerprint=str(
                        semantic_map.fingerprints.get("semantic_overlay") or ""
                    ),
                    report_runner=semantic_delta_runner,
                    mode=str(
                        "active"
                        if ablation_override is not None
                        else getattr(
                            self.base_config.analysis,
                            "security_semantic_enrichment_mode",
                            "shadow",
                        )
                        or "shadow"
                    ),
                )

            coordinator = ActiveDiscoveryCoordinator(
                profile=profile,
                store=store,
                registrar=registrar,
                report_runner=report_runner,
                semantic_enricher=semantic_enricher,
                discovery_enabled=discovery_enabled,
                visibility_mode=(
                    "active"
                    if ablation_override is not None
                    else rollout_active_discovery_mode(self.base_config)
                ),
                rollout_stage=str(
                    (
                        f"benchmark_ablation_{ablation_override.arm_id.lower()}"
                        if ablation_override is not None
                        else rollout_runtime_policy(self.base_config).get("stage") or "unmanaged"
                    )
                ),
            )
            planned_map, discovery_state = coordinator.run(
                semantic_map,
                covered_keys=candidate_coverage_keys(self._candidate_ledger),
                known_variant_keys=self._historical_variant_keys_for_map(semantic_map),
                export_path=export_path,
            )
            state.update(discovery_state)
            try:
                spec_store = SecuritySpecStore(snapshot_dir / "security_specs")
                existing_specs = spec_store.list_specs()
                qualifications = spec_store.list_artifacts("qualification")
                builtin_qualification = load_builtin_qualification()
                qualifications = [
                    builtin_qualification,
                    *(
                        value
                        for value in qualifications
                        if value.get("content_sha256")
                        != builtin_qualification.get("content_sha256")
                    ),
                ]
                evidence_refs = {
                    str(value)
                    for claim in getattr(planned_map, "claims", ()) or ()
                    for value in getattr(claim, "evidence_refs", ()) or ()
                }
                dependency_hashes = {
                    str(value)
                    for record in getattr(planned_map, "functions", ()) or ()
                    for value in (
                        getattr(record, "code_hash", ""),
                        hashlib.sha256(
                            json.dumps(
                                getattr(record, "backend_coverage", {}) or {},
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest(),
                    )
                    if str(value)
                }
                spec_shadow = SecuritySpecShadowRuntime(spec_store).run(
                    planned_map,
                    qualification_hashes=[
                        str(value.get("content_sha256") or "") for value in qualifications
                    ],
                    qualifications=qualifications,
                    resolvable_evidence_refs=evidence_refs,
                    current_dependency_hashes=dependency_hashes,
                    additional_specs=existing_specs,
                )
                state["security_spec_shadow"] = spec_shadow
                self._decision_trace_store.update_identity(
                    {
                        "security_spec_mode": str(
                            spec_shadow.get("security_spec_mode") or "shadow"
                        ),
                        "security_spec_root_manifest_sha256": str(
                            spec_shadow.get("root_manifest_sha256") or ""
                        ),
                        "security_spec_artifact_refs": list(spec_shadow.get("artifact_refs") or []),
                        "security_spec_shadow_decision": {
                            "active_product_effect": "none",
                            "compiled_spec_count": int(
                                spec_shadow.get("compiled_spec_count", 0) or 0
                            ),
                            "reason_code": "security_spec_shadow_only",
                        },
                    }
                )
            except Exception as exc:
                state["security_spec_shadow"] = {
                    "schema_version": "zscope.security-spec-shadow-result.v2",
                    "security_spec_mode": "shadow",
                    "active_product_effect": "none",
                    "status": "failed_closed",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
                self._decision_trace_store.update_identity(
                    {
                        "security_spec_mode": "shadow",
                        "security_spec_artifact_refs": [],
                        "security_spec_shadow_decision": {
                            "active_product_effect": "none",
                            "reason_code": "security_spec_shadow_failed_closed",
                        },
                    }
                )
            planned_units = list(planned_map.audit_units)
            missing_modeling = (
                semantic_enrichment_enabled and modeling_llm_client is None and bool(planned_units)
            )
            missing_discovery = (
                discovery_enabled
                and discovery_llm_client is None
                and int(state.get("completed_report_count", 0) or 0) < len(planned_units)
            )
            if missing_modeling or missing_discovery:
                state["status"] = "planned_no_llm_client"
                missing_roles = [
                    role
                    for role, missing in (
                        ("modeling", missing_modeling),
                        ("analysis", missing_discovery),
                    )
                    if missing
                ]
                state.setdefault("failures", []).append(
                    {
                        "reason": (
                            "No LLM client was configured for required scan role(s): "
                            + ", ".join(missing_roles)
                        )
                    }
                )
                state["uncovered_unit_ids"] = list(
                    dict.fromkeys(
                        [
                            *list(state.get("uncovered_unit_ids") or []),
                            *(unit.unit_id for unit in planned_units),
                        ]
                    )
                )
        except CancellationError:
            state["status"] = "interrupted"
            state["failures"] = [{"reason": "active discovery cancelled"}]
        except Exception as exc:
            state["status"] = "failed"
            state["failures"] = [{"reason": f"{type(exc).__name__}: {exc}"}]
            logger.exception("[active-discovery] stage failed")
        finally:
            state["duration_seconds"] = round(time.monotonic() - started, 4)
            self._active_discovery_state = state
            logger.info(
                "[active-discovery] end profile=%s status=%s units=%d hypotheses=%d "
                "new_groups=%d duration=%.2fs",
                state.get("profile"),
                state.get("status"),
                int(state.get("planned_unit_count", 0) or 0),
                int(state.get("hypothesis_count", 0) or 0),
                int(state.get("new_validation_group_count", 0) or 0),
                state["duration_seconds"],
            )

    def _historical_variant_keys_for_map(self, semantic_map: Any) -> Set[str]:
        """Read prior confirmed reports for the functions in this map."""

        if self.force_ignore_history:
            return set()
        issues: List[Dict[str, Any]] = []
        seen_index_names: Set[str] = set()
        for record in getattr(semantic_map, "functions", ()) or ():
            index_name = str(getattr(record, "index_name", "") or "")
            if not index_name or index_name in seen_index_names:
                continue
            seen_index_names.add(index_name)
            try:
                report = self.snapshot_store.load_final_report(index_name)
            except Exception:
                logger.exception(
                    "[active-discovery] failed to load historical variant report index=%s",
                    index_name,
                )
                continue
            if isinstance(report, dict) and isinstance(report.get("issues"), list):
                issues.extend(item for item in report["issues"] if isinstance(item, dict))
        return historical_variant_keys(issues)

    def _scan_role_llm_client(self, role: str) -> Optional[LLMClient]:
        """Resolve the public role mapping before any legacy Agent config."""

        profiles = getattr(getattr(self.base_config, "scan", None), "llm_profiles", None)
        configured_ref = str(getattr(profiles, role, "") or "")
        if not configured_ref:
            legacy_names = ("active_discovery",) if role == "analysis" else ("semantic_modeler",)
            configured_ref = next(
                (
                    str(getattr(item, "llm_ref", "") or "")
                    for item in self.base_config.project.agents
                    if str(getattr(item, "name", "") or "") in legacy_names
                    and bool(getattr(item, "enabled", True))
                    and str(getattr(item, "llm_ref", "") or "")
                ),
                "",
            )
        configured_ref = configured_ref or "default"
        return self._shared_llm_clients.get(
            configured_ref,
            self._shared_llm_clients.get("default"),
        )

    # Compatibility for integrations that called the former private helper.
    def _active_discovery_llm_client(self) -> Optional[LLMClient]:
        return self._scan_role_llm_client("analysis")

    @staticmethod
    def _build_shared_llm_clients(config: ZScopeConfig) -> Dict[str, LLMClient]:
        clients: Dict[str, LLMClient] = {}
        token_usage_ledger = ensure_scan_token_usage_ledger(config)
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
                retry_until_available=getattr(llm_cfg, "retry_until_available", False),
                max_tokens=llm_cfg.max_tokens,
                base_url_rate_limit_per_minute=getattr(
                    llm_cfg, "base_url_rate_limit_per_minute", 0
                ),
                base_url_max_concurrent_requests=getattr(
                    llm_cfg, "base_url_max_concurrent_requests", 0
                ),
                global_max_concurrent_requests=config.concurrency.llm_max_inflight,
                supports_structured_output=getattr(llm_cfg, "supports_structured_output", False),
                token_usage_ledger=token_usage_ledger,
                llm_ref=name,
            )
        return clients

    def _prioritize_entries_for_execution(
        self, entries: List[FunctionEntry]
    ) -> List[FunctionEntry]:
        """Schedule likely long-running entries first to reduce batch tail idle time."""
        if len(entries) <= 1:
            return list(entries)

        scored = [
            (self._entry_scheduling_score(entry), index, entry)
            for index, entry in enumerate(entries)
        ]
        scored.sort(key=lambda item: (-item[0], item[1]))
        prioritized = [entry for _score, _index, entry in scored]
        if [entry.function_name for entry in prioritized] != [
            entry.function_name for entry in entries
        ]:
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
                if name and name not in {"if", "for", "while", "switch", "return", "sizeof"}
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
                identity_matches = (
                    [match for match in matches if isinstance(match, dict)]
                    if isinstance(matches, list)
                    else []
                )
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
            function_name=str(record.get("function_name") or entry.function_name),
            file_path=file_path or None,
            signature=str(record.get("signature") or entry.signature or "") or None,
        )

    def analyze_functions(
        self,
        function_names: List[str],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
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
        entry_token = self._cancellation_token.child(timeout_seconds=None)

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
                entry_identity=entry.identity_key(self.base_config.project.project_root),
                entry_file_path=entry.normalized_file_path(self.base_config.project.project_root),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                issues=report_dict.get("issues", []),
                audit_observations=report_metadata.get("audit_observations", []),
                candidate_terminal_states=report_dict.get("candidate_terminal_states", []),
                error=(str(report_dict.get("error")) if report_dict.get("error") else None),
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata["entry_budget_overrun_seconds"],
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
                entry_identity=entry.identity_key(self.base_config.project.project_root),
                entry_file_path=entry.normalized_file_path(self.base_config.project.project_root),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                error=reason,
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata["entry_budget_overrun_seconds"],
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
                entry_identity=entry.identity_key(self.base_config.project.project_root),
                entry_file_path=entry.normalized_file_path(self.base_config.project.project_root),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                error=str(e),
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata["entry_budget_overrun_seconds"],
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
        exceeded = bool(normalized_budget is not None and (force_exceeded or overrun_seconds > 0.0))
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
                        (Path(path) for path in self.base_config.project.exclude_paths),
                    ).build()
        return self._shared_local_pattern_semantics

    def _get_shared_semantic_overlay(self) -> Dict[str, Any]:
        if self._shared_semantic_overlay is None:
            with self._shared_semantics_lock:
                if self._shared_semantic_overlay is None:
                    self._shared_semantic_overlay = SemanticOverlayCompiler(
                        self.user_config
                    ).compile()
        return self._shared_semantic_overlay

    def _create_config_for_entry(self, entry: FunctionEntry) -> ZScopeConfig:
        """Create a ZScopeConfig copy with the specified entry and custom prompt."""

        agents = []
        for agent_cfg in self.base_config.project.agents:
            agent_copy = copy(agent_cfg)
            entry_custom_prompt = agent_cfg.entry_custom_prompt
            if entry.custom_prompt and agent_cfg.name == "active_discovery":
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
        # Keep entry-specific focus separate from the configured scan task.
        return config

    def generate_combined_report(
        self, results: Dict[str, ParallelAnalysisResult], output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate a combined report from all parallel analysis results.

        Args:
            results: Dict of function name to analysis result
            output_path: Optional path to save combined report

        Returns:
            Combined report dict
        """
        all_issues: List[Dict[str, Any]] = []
        all_observations: List[Dict[str, Any]] = []
        all_terminal_states: List[Dict[str, Any]] = []
        function_summaries: List[Dict[str, Any]] = []
        total_duration = 0.0
        base_config = getattr(self, "base_config", None)
        project_config = getattr(base_config, "project", None)
        project_root = str(getattr(project_config, "project_root", "") or "")
        project_id = str(
            getattr(project_config, "project_id", "") or Path(project_root).name or "project"
        )
        source_root = str(getattr(project_config, "source_root", "") or "")
        batch_run_id = str(getattr(self, "run_id", "") or "")
        benchmark_ablation_override = getattr(self, "_benchmark_ablation_override", None)
        benchmark_ablation_metadata = (
            benchmark_ablation_override.report_metadata()
            if benchmark_ablation_override is not None
            else None
        )
        rule_candidate_counts: Dict[str, Any] = {
            "by_engine": {},
            "by_rule": {},
            "total": 0,
        }
        all_terminal_states.extend(self._deferred_entry_terminal_states(project_id, project_root))

        for entry_key, result in results.items():
            total_duration += result.duration_seconds
            result_rule_counts = (
                result.metadata.get("rule_candidate_counts", {})
                if isinstance(result.metadata, dict)
                else {}
            )
            if isinstance(result_rule_counts, dict):
                for dimension in ("by_engine", "by_rule"):
                    values = result_rule_counts.get(dimension)
                    if not isinstance(values, dict):
                        continue
                    target = rule_candidate_counts[dimension]
                    for key, value in values.items():
                        target[str(key)] = target.get(str(key), 0) + int(value or 0)
            all_terminal_states.extend(
                item for item in result.candidate_terminal_states if isinstance(item, dict)
            )
            validation_performance = (
                result.metadata.get("validation_performance", {})
                if isinstance(result.metadata, dict)
                else {}
            )

            function_summaries.append(
                {
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
                    "entry_budget_overrun_seconds": round(result.entry_budget_overrun_seconds, 3),
                    "budget_exhaustion_policy": result.budget_exhaustion_policy,
                    "context_tokens": result.context_tokens,
                    "cumulative_prompt_tokens": result.cumulative_prompt_tokens,
                    "cumulative_completion_tokens": result.cumulative_completion_tokens,
                    "cumulative_total_tokens": result.cumulative_total_tokens,
                    "validation_performance": validation_performance,
                    "error": result.error,
                }
            )

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
        snapshot = getattr(
            getattr(self, "_candidate_ledger", None),
            "freeze",
            None,
        )
        if not callable(snapshot):
            raise RuntimeError(
                "live batch report assembly requires a Candidate Ledger; "
                "read historical non-canonical reports through zscope.compat"
            )
        ledger_snapshot = snapshot()
        if not isinstance(ledger_snapshot, dict) or not isinstance(
            ledger_snapshot.get("outcomes"), list
        ):
            raise RuntimeError("Candidate Ledger did not produce frozen outcomes")
        first_metadata = next(
            (
                result.metadata
                for result in results.values()
                if isinstance(result.metadata, dict) and result.metadata
            ),
            {},
        )
        decision_trace_store = getattr(self, "_decision_trace_store", None)
        if not isinstance(decision_trace_store, DecisionTraceStore):
            # Report-only callers and a few compatibility tests construct an
            # analyzer without running __init__.  Keep those paths traceable
            # without writing sidecars into the project working tree.
            decision_trace_store = DecisionTraceStore(
                Path(tempfile.gettempdir()) / f"zscope-report-trace-{uuid.uuid4().hex}",
                identity={"project_id": project_id, "project_root": project_root},
            )
            self._decision_trace_store = decision_trace_store
        decision_trace_store.update_identity(
            {
                "source_revision": str(first_metadata.get("commit_sha") or ""),
                "source_tree_hash": str(first_metadata.get("source_tree_hash") or ""),
                "config_hash": str(first_metadata.get("config_hash") or ""),
                "model_manifest_hash": str(first_metadata.get("model_manifest_hash") or ""),
                "effective_rules_sha256": str(
                    getattr(
                        getattr(base_config, "rule_catalog_provenance", None),
                        "effective_sha256",
                        "",
                    )
                    or ""
                ),
            }
        )
        canonical_projection_state: Dict[str, Any] = {
            "candidate_lifecycle_snapshot": ledger_snapshot,
            "finding_root_projection_enabled": True,
            "decision_trace_store": decision_trace_store,
        }
        canonical_outcomes = (
            ReportAssembler._canonical_outcome_items(canonical_projection_state) or []
        )
        canonical_projection = True
        # A scan-level outcome is authoritative.  Per-entry reports may have
        # been assembled before another entry completed the shared validation
        # future, so they are provenance only at this point.  An empty outcome
        # set is still canonical and must never fall back to raw entry issues.
        all_issues = [
            item
            for item in canonical_outcomes
            if str(item.get("candidate_disposition") or "").lower() == "confirmed"
        ]
        all_observations = [
            item
            for item in canonical_outcomes
            if str(item.get("candidate_disposition") or "").lower() == "needs_review"
        ]
        all_terminal_states = [
            {
                key: value
                for key, value in item.items()
                if key != "issue" and value not in (None, "", [], {})
            }
            for item in canonical_outcomes
        ]

        interrupted = bool(getattr(self, "_interrupted", False))
        unique_issues = list(all_issues)
        unique_observations = list(all_observations)
        unique_terminal_states = [
            dict(item)
            for item in coalesce_terminal_candidates(all_terminal_states)
            if isinstance(item, dict)
        ]
        for item in unique_terminal_states:
            if item.get("decision_trace_ref"):
                continue
            if not item.get("validation_cluster_uid"):
                stable = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
                item["validation_cluster_uid"] = (
                    "VAL_ENGINE_" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:32]
                )
            decision_trace_store.finalize_issue(
                item,
                view_memberships=("excluded",),
            )
        canonical_projection_state["decision_trace_manifest"] = decision_trace_store.snapshot()
        report_views = build_report_views(
            unique_issues,
            unique_observations,
            canonical_projection=canonical_projection,
        )
        view_summary = report_view_summary({"report_views": report_views})
        with_review_view = report_views.get("with_needs_review", {})

        diff_relevance_summary = self._diff_relevance_summary(unique_issues, unique_observations)
        diff_coverage = self._diff_coverage_metadata()
        global_validation_state = dict(getattr(self, "_global_validation_state", {}) or {})
        global_validation_duration = float(
            getattr(self, "_global_validation_duration_seconds", 0.0) or 0.0
        )
        active_discovery_state = dict(getattr(self, "_active_discovery_state", {}) or {})
        active_discovery_duration = float(
            active_discovery_state.get("duration_seconds", 0.0) or 0.0
        )
        total_duration += global_validation_duration
        total_duration += active_discovery_duration
        batch_wall_seconds = round(float(getattr(self, "_last_batch_wall_seconds", 0.0) or 0.0), 2)
        effective_speedup = (total_duration / batch_wall_seconds) if batch_wall_seconds > 0 else 0.0
        worker_utilization = (
            effective_speedup / max(1, int(self.max_workers or 1))
            if batch_wall_seconds > 0
            else 0.0
        )
        validation_performance_summary = self._validation_performance_summary(results)
        entry_budget_summary = self._entry_budget_summary(results)
        llm_iteration_budget_summary = self._llm_iteration_budget_summary(results)
        scan_budget_summary = dict(getattr(self, "_last_scan_budget_metadata", {}) or {})
        llm_usage_summary = self._llm_usage_summary()
        scan_token_usage = scan_token_usage_snapshot(base_config) if base_config is not None else {}
        llm_usage_summary["scan_token_usage"] = scan_token_usage
        retained_prompt_tokens = sum(r.cumulative_prompt_tokens for r in results.values())
        retained_completion_tokens = sum(r.cumulative_completion_tokens for r in results.values())
        retained_total_tokens = sum(r.cumulative_total_tokens for r in results.values())
        retained_prompt_tokens += int(
            global_validation_state.get("total_cumulative_prompt_tokens", 0) or 0
        )
        retained_completion_tokens += int(
            global_validation_state.get("total_cumulative_completion_tokens", 0) or 0
        )
        retained_total_tokens += int(
            global_validation_state.get("total_cumulative_total_tokens", 0) or 0
        )
        retained_prompt_tokens += int(
            active_discovery_state.get("cumulative_prompt_tokens", 0) or 0
        )
        retained_completion_tokens += int(
            active_discovery_state.get("cumulative_completion_tokens", 0) or 0
        )
        retained_total_tokens += int(active_discovery_state.get("cumulative_total_tokens", 0) or 0)
        total_context_tokens = sum(r.context_tokens for r in results.values()) + int(
            global_validation_state.get("total_context_tokens", 0) or 0
        )
        total_context_tokens += int(active_discovery_state.get("context_tokens", 0) or 0)
        response_prompt_tokens = int(llm_usage_summary.get("prompt_tokens") or 0)
        response_completion_tokens = int(llm_usage_summary.get("completion_tokens") or 0)
        response_total_tokens = int(llm_usage_summary.get("total_tokens") or 0)
        engine_capabilities = {
            entry_key: (
                result.metadata.get("engine_capabilities")
                if isinstance(result.metadata, dict)
                else {}
            )
            for entry_key, result in results.items()
        }
        project_fact_state = dict(getattr(self, "_project_fact_pass_state", {}) or {})
        project_rule_counts = project_fact_state.get("rule_candidate_counts")
        if isinstance(project_rule_counts, dict):
            for dimension in ("by_engine", "by_rule"):
                values = project_rule_counts.get(dimension)
                if not isinstance(values, dict):
                    continue
                target = rule_candidate_counts[dimension]
                for key, value in values.items():
                    target[str(key)] = target.get(str(key), 0) + int(value or 0)
        if project_fact_state:
            engine_capabilities["__project_deterministic_fact_pass__"] = {
                "project_deterministic_fact_pass": {
                    "status": str(project_fact_state.get("status") or "complete"),
                    "active": bool(project_fact_state.get("enabled", False)),
                    "candidate_count": int(project_fact_state.get("candidate_count", 0) or 0),
                    "reachable_functions": int(
                        project_fact_state.get("reachable_functions", 0) or 0
                    ),
                    "analyzed_functions": int(project_fact_state.get("analyzed_functions", 0) or 0),
                    "unresolved_internal_functions": int(
                        project_fact_state.get("unresolved_internal_functions", 0) or 0
                    ),
                    "failures": list(project_fact_state.get("failures") or []),
                }
            }
        if active_discovery_state:
            engine_capabilities["__active_discovery__"] = {
                "security_semantic_map": {
                    "status": str(active_discovery_state.get("status") or "not_run"),
                    "active": bool(active_discovery_state.get("enabled", False)),
                    "profile": str(active_discovery_state.get("profile") or "fast"),
                    "planned_unit_count": int(
                        active_discovery_state.get("planned_unit_count", 0) or 0
                    ),
                    "completed_report_count": int(
                        active_discovery_state.get("completed_report_count", 0) or 0
                    ),
                    "hypothesis_count": int(active_discovery_state.get("hypothesis_count", 0) or 0),
                    "new_validation_group_count": int(
                        active_discovery_state.get("new_validation_group_count", 0) or 0
                    ),
                    "failures": list(active_discovery_state.get("failures") or []),
                }
            }
            spec_shadow = active_discovery_state.get("security_spec_shadow")
            if isinstance(spec_shadow, dict):
                engine_capabilities["__security_spec_shadow__"] = {
                    "security_spec": {
                        "status": str(spec_shadow.get("status") or "complete"),
                        "mode": str(spec_shadow.get("security_spec_mode") or "shadow"),
                        "active_product_effect": str(
                            spec_shadow.get("active_product_effect") or "none"
                        ),
                        "mined_spec_count": int(spec_shadow.get("mined_spec_count", 0) or 0),
                        "compiled_spec_count": int(spec_shadow.get("compiled_spec_count", 0) or 0),
                        "root_manifest_sha256": str(spec_shadow.get("root_manifest_sha256") or ""),
                        "artifact_refs": list(spec_shadow.get("artifact_refs") or []),
                    }
                }
        error_result_count = sum(
            1
            for result in results.values()
            if bool(result.error) or str(result.verdict).lower() == "error"
        )

        rule_candidate_counts["by_engine"] = dict(
            sorted(rule_candidate_counts["by_engine"].items())
        )
        rule_candidate_counts["by_rule"] = dict(sorted(rule_candidate_counts["by_rule"].items()))
        rule_candidate_counts["total"] = sum(rule_candidate_counts["by_rule"].values())
        effective_rules = getattr(base_config, "effective_rules", None)
        global_validation_report = {
            "enabled": self._uses_scan_validation_queue(),
            "duration_seconds": round(global_validation_duration, 4),
            "unique_group_count": int(
                global_validation_state.get("validation_group_count", 0) or 0
            ),
            "raw_occurrence_count": int(
                global_validation_state.get("scan_level_raw_occurrence_count", 0) or 0
            ),
            "drained": bool(global_validation_state.get("validation_queue_drained", False)),
            "validator_session_count": int(
                global_validation_state.get("validator_session_count", 0) or 0
            ),
            "validator_api_call_count": int(
                global_validation_state.get("validator_api_call_count", 0) or 0
            ),
            "validator_turn_distribution": dict(
                global_validation_state.get("validator_turn_distribution") or {}
            ),
            "validator_prompt_tokens_by_stage": dict(
                global_validation_state.get("validator_prompt_tokens_by_stage") or {}
            ),
            "evidence_slice_token_count": int(
                global_validation_state.get("evidence_slice_token_count", 0) or 0
            ),
            "multi_turn_outlier_count": int(
                global_validation_state.get("multi_turn_outlier_count", 0) or 0
            ),
            "fact_request_count": int(
                global_validation_state.get("validator_fact_request_count", 0) or 0
            ),
            "fact_resolution_success_count": int(
                global_validation_state.get("validator_fact_resolution_success_count", 0) or 0
            ),
            "fact_resolution_success_rate": global_validation_state.get(
                "validator_fact_resolution_success_rate"
            ),
            "fact_resolution_by_kind": dict(
                global_validation_state.get("validator_fact_resolution_by_kind") or {}
            ),
            "fact_terminal_status_counts": dict(
                global_validation_state.get("validator_fact_terminal_status_counts") or {}
            ),
            "evidence_recheck_count": int(
                global_validation_state.get("validator_evidence_recheck_count", 0) or 0
            ),
            "targeted_investigation_count": int(
                global_validation_state.get("validator_targeted_investigation_count", 0) or 0
            ),
            "verdict_transitions": dict(
                global_validation_state.get("validator_verdict_transitions") or {}
            ),
        }
        combined_report = {
            "rule_catalog": (
                serialize_effective_rules(effective_rules) if effective_rules is not None else {}
            ),
            "rule_candidate_counts": rule_candidate_counts,
            "type": "parallel_analysis_report",
            "summary": {
                "functions_analyzed": len(results),
                "functions_scheduled": len(results),
                "functions_completed": len(results) - error_result_count,
                "functions_failed": error_result_count,
                "total_issues": len(unique_issues),
                "unique_issues": len(unique_issues),
                "audit_observations": len(unique_observations),
                "deferred_entry_count": len(getattr(self, "deferred_entry_candidates", []) or []),
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
                "total_cumulative_total_tokens": (response_total_tokens or retained_total_tokens),
                "retained_entry_prompt_tokens": retained_prompt_tokens,
                "retained_entry_completion_tokens": retained_completion_tokens,
                "retained_entry_total_tokens": retained_total_tokens,
                "llm_usage": llm_usage_summary,
                "parallel_speedup": f"{effective_speedup:.2f}x observed (using {self.max_workers} workers)",
                "parallel_worker_utilization": round(worker_utilization, 4),
                "diff_relevance": diff_relevance_summary["issues"],
                "diff_coverage": diff_coverage.get("coverage_summary", {}),
                "validation_performance": validation_performance_summary,
                "global_validation_queue": dict(global_validation_report),
                "project_deterministic_fact_pass": project_fact_state,
                "active_discovery": active_discovery_state,
                "benchmark_ablation": benchmark_ablation_metadata,
                "entry_budget": entry_budget_summary,
                "llm_iteration_budget": llm_iteration_budget_summary,
                "scan_budget": scan_budget_summary,
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
                        if isinstance(result.metadata, dict) and result.metadata.get("commit_sha")
                    ),
                    "",
                ),
                "config_hash": next(
                    (
                        str(result.metadata.get("config_hash") or "")
                        for result in results.values()
                        if isinstance(result.metadata, dict) and result.metadata.get("config_hash")
                    ),
                    "",
                ),
                "effective_rules_sha256": str(
                    getattr(
                        getattr(base_config, "rule_catalog_provenance", None),
                        "effective_sha256",
                        "",
                    )
                    or ""
                ),
                "rule_catalog": (
                    serialize_effective_rules(effective_rules)
                    if effective_rules is not None
                    else {}
                ),
                "rule_candidate_counts": rule_candidate_counts,
                "runtime_spec": (
                    dict(vars(getattr(base_config, "runtime_provenance", None)))
                    if getattr(base_config, "runtime_provenance", None) is not None
                    else {}
                ),
                "scan_depth": str(getattr(getattr(base_config, "scan", None), "depth", "fast")),
                "effective_scan": {
                    "depth": str(getattr(getattr(base_config, "scan", None), "depth", "fast")),
                    "depth_source": str(
                        getattr(
                            getattr(base_config, "scan", None),
                            "depth_source",
                            "default",
                        )
                        or "default"
                    ),
                    "rollout": rollout_runtime_policy(base_config),
                },
                "rollout": rollout_runtime_policy(base_config),
                "llm_usage": scan_token_usage,
                "audit_observation_count": len(unique_observations),
                "audit_observations": unique_observations,
                "report_view_summary": view_summary,
                "diff_relevance_summary": diff_relevance_summary,
                "diff_impact_coverage": diff_coverage,
                "context_tokens": total_context_tokens,
                "cumulative_prompt_tokens": (response_prompt_tokens or retained_prompt_tokens),
                "cumulative_completion_tokens": (
                    response_completion_tokens or retained_completion_tokens
                ),
                "cumulative_total_tokens": (response_total_tokens or retained_total_tokens),
                "retained_entry_prompt_tokens": retained_prompt_tokens,
                "retained_entry_completion_tokens": retained_completion_tokens,
                "retained_entry_total_tokens": retained_total_tokens,
                "llm_usage": llm_usage_summary,
                "validation_performance": validation_performance_summary,
                "global_validation_queue": dict(global_validation_report),
                "project_deterministic_fact_pass": project_fact_state,
                "active_discovery": active_discovery_state,
                "benchmark_ablation": benchmark_ablation_metadata,
                "entry_budget": entry_budget_summary,
                "llm_iteration_budget": llm_iteration_budget_summary,
                "scan_budget": scan_budget_summary,
                "engine_capabilities": engine_capabilities,
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
                "llm_usage": scan_token_usage,
                "finding_root_projection_enabled": True,
                "finding_root_count": int(
                    canonical_projection_state.get("finding_root_count", 0) or 0
                ),
                "finding_root_alias_count": int(
                    canonical_projection_state.get("finding_root_alias_count", 0) or 0
                ),
                "finding_root_projection_summary": dict(
                    canonical_projection_state.get("finding_root_projection_summary") or {}
                ),
                "decision_trace_manifest": dict(
                    canonical_projection_state.get("decision_trace_manifest") or {}
                ),
                "budget_exhaustion_policy": str(
                    global_validation_state.get("budget_exhaustion_policy") or "observe"
                ),
                "validation_queue_drained": bool(
                    global_validation_state.get("validation_queue_drained", False)
                ),
                "validator_session_count": int(
                    global_validation_state.get("validator_session_count", 0) or 0
                ),
                "validator_api_call_count": int(
                    global_validation_state.get("validator_api_call_count", 0) or 0
                ),
                "validator_turn_distribution": dict(
                    global_validation_state.get("validator_turn_distribution") or {}
                ),
                "validator_prompt_tokens_by_stage": dict(
                    global_validation_state.get("validator_prompt_tokens_by_stage") or {}
                ),
                "evidence_slice_token_count": int(
                    global_validation_state.get("evidence_slice_token_count", 0) or 0
                ),
                "multi_turn_outlier_count": int(
                    global_validation_state.get("multi_turn_outlier_count", 0) or 0
                ),
                "snapshot_model_call_count": int(
                    global_validation_state.get("snapshot_model_call_count", 0) or 0
                ),
                "fact_query_cache_hit_count": int(
                    global_validation_state.get("fact_query_cache_hit_count", 0) or 0
                ),
            },
            issues=unique_issues,
            observations=unique_observations,
            metadata=combined_report["metadata"],
            entry_function="__batch__",
        )
        if benchmark_ablation_override is not None:
            combined_report["answer_material_present"] = False
            combined_report["release_eligible"] = False
            combined_report["formal_eligible"] = False
        from ..benchmarking.protocol import candidate_funnel

        combined_report["metadata"]["candidate_funnel"] = candidate_funnel(combined_report)

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
                    "deferred_reason": candidate.get("deferred_reason") or "entry_discovery_budget",
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
        summary: Dict[str, Any] = {key: 0 for key in keys}
        for result in results.values():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            raw_perf = metadata.get("validation_performance")
            perf: Dict[str, Any] = raw_perf if isinstance(raw_perf, dict) else {}
            for key in keys:
                try:
                    summary[key] += int(perf.get(key, 0) or 0)
                except (TypeError, ValueError):
                    continue
        raw_global_state = getattr(self, "_global_validation_state", {})
        global_state: Dict[str, Any] = (
            raw_global_state if isinstance(raw_global_state, dict) else {}
        )
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
            global_state.get("eligible_alias_occurrence_count", raw_occurrences) or 0
        )
        eligible_groups = int(global_state.get("eligible_validation_group_count", scan_groups) or 0)
        eligible_aliases = max(0, eligible_occurrences - eligible_groups)
        summary["eligible_alias_occurrence_count"] = eligible_occurrences
        summary["eligible_validation_group_count"] = eligible_groups
        summary["eligible_coalescing_rate"] = (
            round(eligible_aliases / eligible_occurrences, 4) if eligible_occurrences else 1.0
        )
        summary["all_occurrence_reduction_rate"] = (
            round(grouped_aliases / raw_occurrences, 4) if raw_occurrences else 1.0
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
            round(grouped_aliases / raw_occurrences, 4) if raw_occurrences else 1.0
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
            result for result in results.values() if result.entry_budget_seconds is not None
        ]
        exceeded = [result for result in budgeted if result.entry_budget_exceeded]
        policies = sorted(
            {str(result.budget_exhaustion_policy or "observe") for result in results.values()}
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
                    (result.entry_budget_overrun_seconds for result in exceeded),
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
            "hard_failure_count": sum(1 for item in observations if item.get("hard_failure")),
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

        totals: Dict[str, Any] = {
            "successful_calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "estimated_calls": 0,
            "provider_reported_calls": 0,
        }
        per_client: List[Dict[str, Any]] = []
        call_wall_seconds_total = 0.0
        call_wall_seconds_p50 = 0.0
        call_wall_seconds_p95 = 0.0
        call_wall_seconds_max = 0.0
        for row in unique.values():
            snapshotter = getattr(row["client"], "usage_snapshot", None)
            if not callable(snapshotter):
                continue
            raw = snapshotter()
            snapshot = dict(raw) if isinstance(raw, dict) else {}
            for key in totals:
                totals[key] += int(snapshot.get(key) or 0)
            call_wall_seconds_total += float(
                snapshot.get("successful_call_wall_seconds_total") or 0.0
            )
            call_wall_seconds_p50 = max(
                call_wall_seconds_p50,
                float(snapshot.get("successful_call_wall_seconds_p50") or 0.0),
            )
            call_wall_seconds_p95 = max(
                call_wall_seconds_p95,
                float(snapshot.get("successful_call_wall_seconds_p95") or 0.0),
            )
            call_wall_seconds_max = max(
                call_wall_seconds_max,
                float(snapshot.get("successful_call_wall_seconds_max") or 0.0),
            )
            per_client.append(
                {
                    "llm_refs": sorted(set(row["refs"])),
                    **snapshot,
                }
            )

        successful_calls = totals["successful_calls"]
        totals["provider_usage_coverage"] = round(
            (totals["provider_reported_calls"] / successful_calls if successful_calls else 0.0),
            4,
        )
        totals["successful_call_wall_seconds_total"] = round(call_wall_seconds_total, 4)
        totals["successful_call_wall_seconds_mean"] = round(
            call_wall_seconds_total / successful_calls if successful_calls else 0.0,
            4,
        )
        # Benchmarks normally use one effective profile. For multiple clients these are
        # conservative maxima; per-client distributions remain available below.
        totals["successful_call_wall_seconds_p50"] = round(call_wall_seconds_p50, 4)
        totals["successful_call_wall_seconds_p95"] = round(call_wall_seconds_p95, 4)
        totals["successful_call_wall_seconds_max"] = round(call_wall_seconds_max, 4)
        return {
            **totals,
            "accounting_scope": "successful_response_boundary",
            "failed_or_disconnected_request_usage": "unknown",
            "per_client": per_client,
        }

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

        affected_path_nodes: Set[str] = set()
        affected_path_pairs: Set[tuple[str, str]] = set()
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
        elif (
            issue_func
            and issue_func in affected_path_nodes
            and (not issue_file or not saw_path_refs)
        ):
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
            and (
                left_norm == right_norm
                or left_norm.endswith("/" + right_norm)
                or right_norm.endswith("/" + left_norm)
            )
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
            if (
                value.startswith("[增量]")
                or value.startswith("[存量]")
                or value.startswith("[影响待确认]")
            ):
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
        self, results: Dict[str, ParallelAnalysisResult], output_path: Path
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
            "deferred_entries": len(getattr(self, "deferred_entry_candidates", []) or []),
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
        coverage_summary = (
            diff_coverage.get("coverage_summary") if isinstance(diff_coverage, dict) else {}
        )
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
            display_name = (
                res.function_name if name == res.function_name else f"{res.function_name} ({name})"
            )
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

                    issue_key = (
                        f"{issue.get('location', 'N/A')}:{issue.get('description', '')[:50]}"
                    )
                    if issue_key in seen_in_entry:
                        continue
                    seen_in_entry.add(issue_key)

                    impact = str(issue.get("impact_level", "UNKNOWN")).upper()
                    conf = issue.get("confidence", "N/A")
                    if isinstance(conf, float):
                        conf = f"{conf:.2f}"

                    snippet = issue.get("code_snippet")
                    md.extend(
                        [
                            f"#### {idx}. [{impact}] {issue.get('id', f'ISSUE_{idx}')}: {issue.get('function', 'N/A')}",
                            f"- **Location**: `{issue.get('location', 'N/A')}`",
                            f"- **Confidence**: `{conf}`",
                            f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                        ]
                    )
                    if snippet:
                        md.append(
                            f"- **Relevant Code**:\n```c\n{self._normalize_md_text(snippet)}\n```"
                        )

                    md.append(
                        f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}"
                    )

                    # Add reasoning if present
                    reasoning = issue.get("reasoning")
                    if reasoning:
                        md.append(f"- **Analysis Reasoning**: {self._normalize_md_text(reasoning)}")

                    md.append(
                        f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}"
                    )
                    md.append(
                        f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}"
                    )

                    # Add validation status and reasoning
                    val_status = issue.get("validation_status")
                    if val_status:
                        status_emoji = {
                            "validated": "✅",
                            "rejected": "❌",
                            "pending": "⏳",
                            "unvalidated": "⚠️",
                        }.get(val_status, "")
                        md.append(f"- **Validation Status**: {status_emoji} {val_status}")

                        val_reasoning = issue.get("validation_reasoning")
                        if val_reasoning:
                            md.append(
                                f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}"
                            )

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
                    md.extend(
                        [
                            f"#### {idx}. [{impact}] {issue.get('id', f'REVIEW_{idx}')}: {issue.get('function', 'N/A')}",
                            f"- **Location**: `{issue.get('location', 'N/A')}`",
                            f"- **Confidence**: `{conf}`",
                            f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                            f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}",
                            f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}",
                            f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}",
                        ]
                    )
                    val_reasoning = issue.get("validation_reasoning")
                    if val_reasoning:
                        md.append(
                            f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}"
                        )
                    md.append("")

        content = "\n".join(md)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Markdown report saved to: {output_path}")
        return content

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

    def _group_by_severity(self, issues: List[Dict]) -> Dict[str, List[Dict]]:
        """Group issues by impact level."""
        groups: Dict[str, List[Dict[str, Any]]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        for issue in issues:
            level = issue.get("impact_level", "medium").lower()
            if level in groups:
                groups[level].append(issue)
            else:
                groups["medium"].append(issue)

        return groups
