"""Validation runner that orchestrates Validator calls and dispositions."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import Event, Lock
from typing import Any, Callable, Dict, List, Optional, cast

from ...agents.validator_agent.agent import ValidatorAgent
from ...common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from ...common.issue_identity import canonical_issue_key, deduplicate_issues, issue_build_context_id
from .execution_context import (
    EMPTY_EXECUTION_CONTEXT,
    ExecutionContext,
    rebound_execution_context,
)
from ...config.function_entry import FunctionEntry
from ...framework.llm_client import LLMClient
from ...orchestration.scheduler import VALIDATOR_ROLE, ScanScheduler
from ...orchestration.candidate_envelope import (
    CANDIDATE_SCHEMA_VERSION,
    DECISION_CONTEXT_VERSION,
)
from .evidence import (
    VALIDATOR_EVIDENCE_SLICE_V3,
    VALIDATOR_MISSING_FACT_KINDS,
    build_validator_evidence_slice_v3,
    build_validation_evidence_pack,
    compact_validation_evidence_pack,
    compact_validation_finding,
    is_entry_root_dead_code_rejection,
    normalize_missing_fact_kinds,
    trim_code,
    validation_verdict,
)
from ...common.validator_protocol import (
    VALIDATOR_PROTOCOL_VERSION as VALIDATOR_PROTOCOL_V3,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
)


def _as_dict(value: Any) -> Dict[str, Any]:
    """Narrow dynamic validation payloads while preserving their identity."""
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


from .pipeline import ValidationOutcome, ValidationPipeline
from .evidence_completion import EvidenceCompletionQueue
from .explanation import apply_decision_explanations
from .dynamic_reproduction import (
    DynamicReproductionError,
    attempt_dynamic_reproduction,
    make_dynamic_reproduction_policy,
    release_issue_dynamic_reproduction_authority,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _PreparedValidation:
    index: int
    raw_issue: Dict[str, Any]
    issue_func: str
    issue_code: str
    evidence_pack: Dict[str, Any]
    allow_v3: bool = False
    v3_max_iterations: int = 0


@dataclass
class _ValidationWorkerResult:
    index: int
    raw_issue: Dict[str, Any]
    issue_func: str
    success: bool
    val_data: Dict[str, Any] = field(default_factory=dict)
    error: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence_pack: Dict[str, Any] = field(default_factory=dict)


class ValidationResultCache:
    """Bounded scan-level cache with in-flight coalescing.

    A cache instance belongs to one immutable scan.  Concurrent entry analyzers
    that produce the same semantic validation-group key share one Validator
    call. Occurrence-only entry wrappers are excluded; decision constraints,
    code, model, prompt, tool policy, and revision remain isolated.
    """

    def __init__(self, max_entries: int = 4096) -> None:
        self.max_entries = max(0, int(max_entries or 0))
        self.enabled = self.max_entries > 0
        self._values: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._inflight: Dict[str, Event] = {}
        self._lock = Lock()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if not self.enabled or not key:
            return None
        with self._lock:
            value = self._values.get(key)
            if value is not None:
                self._values.move_to_end(key)
            return dict(value) if isinstance(value, dict) else None

    def reserve(self, key: str) -> bool:
        """Return True to the single owner responsible for computing ``key``."""
        if not self.enabled or not key:
            return True
        with self._lock:
            if key in self._values or key in self._inflight:
                return False
            self._inflight[key] = Event()
            return True

    def wait(self, key: str, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        if not self.enabled or not key:
            return None
        with self._lock:
            event = self._inflight.get(key)
        if event is not None:
            deadline = time.monotonic() + max(0.0, float(timeout)) if timeout is not None else None
            while not event.is_set():
                token = current_cancellation_token()
                if token is not None:
                    token.raise_if_cancelled()
                wait_seconds = 0.05
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    wait_seconds = min(wait_seconds, remaining)
                event.wait(timeout=wait_seconds)
        return self.get(key)

    def put(self, key: str, value: Dict[str, Any]) -> None:
        if not self.enabled or not key or not isinstance(value, dict):
            return
        with self._lock:
            self._values[key] = dict(value)
            self._values.move_to_end(key)
            while len(self._values) > self.max_entries:
                self._values.popitem(last=False)
            event = self._inflight.pop(key, None)
        if event is not None:
            event.set()

    def abandon(self, key: str) -> None:
        if not self.enabled or not key:
            return
        with self._lock:
            event = self._inflight.pop(key, None)
        if event is not None:
            event.set()

    def discard(self, key: str) -> None:
        """Remove a non-reusable value and release any coalesced waiters."""

        if not self.enabled or not key:
            return
        with self._lock:
            self._values.pop(key, None)
            event = self._inflight.pop(key, None)
        if event is not None:
            event.set()


class ValidationRunner:
    """Owns validation-stage orchestration around ``ValidationPipeline``."""

    # v5 invalidates v4 entries after source-centric validation groups stopped
    # carrying occurrence-only reachability projections.
    _VALIDATION_CACHE_PROTOCOL = "zscope.validator-cache.v12"
    _DEFAULT_VALIDATION_CACHE_SIZE = 4096
    _TRANSIENT_VALIDATOR_STOP_REASONS = frozenset(
        {
            "fact_timeout",
            "malformed_output",
            "output_truncated",
        }
    )

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
        deduplicate_issues_fn: Callable[
            [List[Dict[str, Any]]], List[Dict[str, Any]]
        ] = deduplicate_issues,
        validator_agent_factory: Callable[..., Any] = ValidatorAgent,
        result_cache: Optional[ValidationResultCache] = None,
        scheduler: Optional[ScanScheduler] = None,
        project_knowledge_service: Optional[Any] = None,
        get_contract_registry: Optional[Callable[[], Any]] = None,
        reproduction_service: Any = None,
        instance_scope: Optional[Any] = None,
        input_current_guard: Optional[Callable[[], None]] = None,
        instance_semantics_digest: str = "",
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
        self._input_current_guard = input_current_guard
        self._instance_semantics_digest = instance_semantics_digest
        self.issue_key_fn = issue_key_fn
        self.deduplicate_issues = deduplicate_issues_fn
        self.validator_agent_factory = validator_agent_factory
        self.scheduler = scheduler
        # Optional read-only Wiki/source resolver.  It is intentionally
        # injected rather than constructed inside Validator threads so one
        # scan pins a single manifest/revision and cache identity.
        self.project_knowledge_service = project_knowledge_service
        self.get_contract_registry = get_contract_registry
        self.reproduction_service = reproduction_service
        self._review_checker_instance: Any = None
        self._review_init_lock = Lock()
        # The exact build instance this runner validates for: an explicit
        # scope, or the ScopedCodeIndex facade's pinned instance.  None means
        # the runner is not instance-scoped and binds an empty scope so it
        # never inherits another variant's leftover binding.
        self._instance_scope = (
            instance_scope if instance_scope is not None else getattr(code_index, "scope", None)
        )
        # Validator verdicts are contextual.  Keeping this cache on the runner
        # scopes it to one immutable scan instead of leaking decisions between
        # projects, revisions, entries, or long-lived service requests.
        self._validator_result_cache_size = self._validation_cache_size()
        self._validator_result_cache = result_cache or ValidationResultCache(
            self._validator_result_cache_size
        )
        self._validation_environment_fingerprint = self._build_validation_environment_fingerprint()
        self._decision_explanations_used = 0
        self._evidence_completion_queue = EvidenceCompletionQueue(
            enabled=True,
            max_workers=config.concurrency.evidence_completion_workers,
            enable_v11_providers=True,
            enable_v12_providers=True,
        )

    @property
    def _scoped_build_id(self) -> str:
        scope = self._instance_scope
        return str(getattr(scope, "build_context_id", "") or "") if scope is not None else ""

    @property
    def _scoped_usr(self) -> str:
        scope = self._instance_scope
        return str(getattr(scope, "usr", "") or "") if scope is not None else ""

    @property
    def _execution_context(self) -> ExecutionContext:
        """This runner's precise build/entry scope as a portable context.

        Scoped runners pin their instance's build id and the analyzed
        function's own ``(name, usr)`` entry symbol; unscoped runners carry
        the empty context so their workers never inherit an ambient variant
        binding from the submitting thread.
        """
        scope = self._instance_scope
        if scope is None:
            return EMPTY_EXECUTION_CONTEXT
        names = getattr(scope, "function_names", ()) or ()
        entry_name = str(names[0]) if names else ""
        return ExecutionContext(
            build_context_id=str(getattr(scope, "build_context_id", "") or ""),
            entry_symbol=(entry_name, str(getattr(scope, "usr", "") or "")),
        )

    def _bind_validation_scope(self):
        """Bind this runner's exact execution context for the current thread.

        The portable :class:`ExecutionContext` is also what inner workers
        (the evidence-completion fact-provider pool) capture at submit time
        and rebind on their own threads, so the whole validation chain runs
        under one precise, finally-restored scope.
        """
        return rebound_execution_context(self._execution_context)

    def _scoped_validate_with_deadline(
        self,
        item: _PreparedValidation,
        *,
        parent_token: Optional[CancellationToken],
        validator_agent: Optional[Any] = None,
    ) -> _ValidationWorkerResult:
        """Worker entry: explicitly bind this runner's scope, then validate.

        Pool and scheduler threads are reused across tasks and scans; each
        task states its own precise build context and restores the thread's
        previous value on the way out (including on cancellation/error paths,
        via the context manager's finally).
        """
        with self._bind_validation_scope():
            return self._validate_with_deadline(
                item, parent_token=parent_token, validator_agent=validator_agent
            )

    def run(self, state: Dict[str, Any]) -> None:
        self._require_current_inputs()
        with self._bind_validation_scope():
            self._run_validation(state)
        self._require_current_inputs()

    def _require_current_inputs(self) -> None:
        guard = getattr(self, "_input_current_guard", None)
        if guard is not None:
            guard()

    def _run_validation(self, state: Dict[str, Any]) -> None:
        new_issues = state.get("pending_new_issues", [])
        if not new_issues:
            state["validation_queue_drained"] = True
            return

        deduped_issues = self._coalesce_validation_groups(new_issues)
        state["validation_group_count"] = int(state.get("validation_group_count", 0) or 0) + len(
            deduped_issues
        )
        if len(deduped_issues) != len(new_issues):
            merged_count = len(new_issues) - len(deduped_issues)
            state["validation_group_merged_count"] = (
                int(state.get("validation_group_merged_count", 0) or 0) + merged_count
            )
            logger.info("Merged %d duplicate candidate issue(s) before validation.", merged_count)
            state["notes"].append(
                f"Merged {merged_count} duplicate candidate issue(s) before validation."
            )
        new_issues = deduped_issues

        if not self._validator_enabled():
            self._mark_unvalidated(state, new_issues)
            state["pending_new_issues"] = []
            state["validation_queue_drained"] = True
            return

        prepared = []
        for index, raw_issue in enumerate(new_issues):
            item = self._prepare_issue_for_validation(state, raw_issue, index)
            if item is not None:
                prepared.append(item)

        prepared = self._assign_v3_investigation_budget(prepared)

        validation_workers = self._validation_worker_count(len(prepared))
        parent_token = current_cancellation_token()
        if parent_token is not None:
            parent_token.raise_if_cancelled()
        if validation_workers <= 1 and self.scheduler is None:
            validator_agent = self._build_validator_agent() if prepared else None
            for item in prepared:
                if parent_token is not None:
                    parent_token.raise_if_cancelled()
                result = self._validate_with_deadline(
                    item,
                    parent_token=parent_token,
                    validator_agent=validator_agent,
                )
                self._apply_validation_worker_result(state, result)
        elif prepared:
            logger.info(
                "Validating %d issue(s) with %d validator worker(s).",
                len(prepared),
                validation_workers,
            )
            results: Dict[int, _ValidationWorkerResult] = {}
            executor: Optional[ThreadPoolExecutor] = None
            hard_cancelled = False
            future_to_item: Dict[Future[Any], _PreparedValidation] = {}
            if self.scheduler is None:
                executor = ThreadPoolExecutor(
                    max_workers=validation_workers,
                    thread_name_prefix="zscope-validator",
                )
            try:
                for item in prepared:
                    if parent_token is not None:
                        parent_token.raise_if_cancelled()
                    if self.scheduler is not None:
                        future = self.scheduler.submit(
                            VALIDATOR_ROLE,
                            self._scoped_validate_with_deadline,
                            item,
                            parent_token=parent_token,
                            priority=int(item.raw_issue.get("priority_score") or 0),
                        )
                    else:
                        assert executor is not None
                        future = executor.submit(
                            self._scoped_validate_with_deadline,
                            item,
                            parent_token=parent_token,
                        )
                    future_to_item[future] = item

                pending = set(future_to_item)
                while pending:
                    if parent_token is not None and parent_token.is_cancelled():
                        hard_cancelled = True
                        self._cancel_validation_futures(pending)
                        parent_token.raise_if_cancelled()

                    wait_timeout = self._cancellation_poll_seconds(parent_token)
                    completed, pending = wait(
                        pending,
                        timeout=wait_timeout,
                        return_when=FIRST_COMPLETED,
                    )
                    if parent_token is not None and parent_token.is_cancelled():
                        hard_cancelled = True
                        self._cancel_validation_futures(pending)
                        parent_token.raise_if_cancelled()

                    for future in completed:
                        item = future_to_item[future]
                        try:
                            results[item.index] = future.result()
                        except CancellationError:
                            hard_cancelled = True
                            self._cancel_validation_futures(pending)
                            raise
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
                if parent_token is not None:
                    parent_token.raise_if_cancelled()
            except CancellationError:
                hard_cancelled = True
                self._cancel_validation_futures(future_to_item)
                raise
            finally:
                if executor is not None:
                    executor.shutdown(
                        wait=not hard_cancelled,
                        cancel_futures=hard_cancelled,
                    )
            for item in prepared:
                self._apply_validation_worker_result(state, results[item.index])

        self._supplement_decision_explanations(state)
        if self._review_facts_enabled() and not state.get("_validating_review_appendix"):
            self._validate_related_candidates(state, new_issues)
        if self._review_enabled():
            for issue in new_issues:
                self._review_checkpoint(issue, "final_disposition")
        state["pending_new_issues"] = []
        state["validation_queue_drained"] = True

    def replay_review_candidate(
        self,
        candidate: Dict[str, Any],
        prior_result: Dict[str, Any],
        *,
        investigate_uncertain: bool,
        audit_rejection: bool,
    ) -> Dict[str, Any]:
        """Resume an answer-free checkpoint through the real final policy.

        This entry point does not accept truth/labels or alter confidence
        thresholds. Experiment controls choose a pass; outcome routing stays
        identical to an ordinary scan.
        """
        from ...orchestration.candidates import CandidateLedger
        from .review_checkpoint import assert_answer_free

        assert_answer_free(candidate)
        assert_answer_free(prior_result)
        if prior_result.get("candidate_uid") != candidate.get("candidate_uid") or prior_result.get(
            "validation_cluster_uid"
        ) != candidate.get("validation_cluster_uid"):
            raise ValueError("prior result identity does not match the frozen candidate")
        with self._bind_validation_scope():
            return self._replay_review_candidate_locked(
                candidate,
                prior_result,
                investigate_uncertain=investigate_uncertain,
                audit_rejection=audit_rejection,
            )

    def _replay_review_candidate_locked(
        self,
        candidate: Dict[str, Any],
        prior_result: Dict[str, Any],
        *,
        investigate_uncertain: bool,
        audit_rejection: bool,
    ) -> Dict[str, Any]:
        from ...orchestration.candidates import CandidateLedger

        issue = deepcopy(candidate)
        for key in (
            "review_checked_proof",
            "review_adjudication",
            "review_disposition_reason",
            "review_priority_signal",
            "review_claim_checks",
        ):
            issue.pop(key, None)
        issue["_review_restore_evidence"] = True
        issue["review_checked_proofs_enabled"] = self._checked_proofs_enabled()
        issue["demote_source_lifecycle_confirm"] = self._depth_scoped_flag(
            "validation_demote_source_lifecycle_confirm"
        )
        issue["obligation_infunction_release_guard"] = self._depth_scoped_flag(
            "validation_obligation_infunction_release_guard"
        )
        uncertain_replay_review = self._depth_scoped_flag("validation_uncertain_replay_review")
        issue["validation_uncertain_replay_review"] = uncertain_replay_review
        # Canonical per-feature measurement flags (validation_*).
        issue["validation_demote_source_lifecycle_confirm"] = issue[
            "demote_source_lifecycle_confirm"
        ]
        issue["validation_obligation_infunction_release_guard"] = issue[
            "obligation_infunction_release_guard"
        ]
        issue["validation_checked_proofs"] = issue["review_checked_proofs_enabled"]
        ledger = CandidateLedger(
            project_root=str(self.config.project.project_root),
            revision=str(issue.get("revision") or ""),
        )
        ledger.restore_review_candidate(issue)
        ledger.freeze()
        function = str(issue.get("function") or "")
        code = str((self._get_function_impl(function) or {}).get("code") or "")
        state: Dict[str, Any] = {
            "candidate_ledger": ledger,
            "entry_func": function,
            "agent_context": {"func_name": function, "code": code},
            "issues": [],
            "observations": [],
            "notes": [],
            "pending_new_issues": [issue],
        }
        item = self._prepare_issue_for_validation(state, issue, 0)
        if item is not None:
            metadata = self._empty_token_metadata()
            data = deepcopy(prior_result)
            if investigate_uncertain and validation_verdict(data) == "uncertain":
                data = self._run_v3_targeted_investigation(
                    replace(item, allow_v3=True, v3_max_iterations=50),
                    self._build_validator_agent(),
                    data,
                    metadata,
                )
            if audit_rejection and validation_verdict(data) == "rejected":
                data = self._run_v2b_adjudication(
                    item, self._build_validator_agent(), data, metadata
                )
            # M1 guard: a positive-case escalation that starts from
            # ``uncertain`` and ends ``verified`` loses its auto-confirm
            # authority; the pipeline forces needs_review via this marker.
            if (
                uncertain_replay_review
                and investigate_uncertain
                and validation_verdict(data) == "verified"
            ):
                issue["review_disposition_reason"] = "uncertain_confirm_hold"
            self._apply_validation_worker_result(
                state,
                _ValidationWorkerResult(
                    index=0,
                    raw_issue=issue,
                    issue_func=function,
                    success=True,
                    val_data=data,
                    metadata=metadata,
                    evidence_pack=item.evidence_pack,
                ),
            )
        if self._review_facts_enabled():
            self._validate_related_candidates(state, [issue])
        self._review_checkpoint(issue, "replay_final")
        return {
            "candidate": issue,
            "related": state.get("review_related_candidates", []),
            "lifecycle": ledger.lifecycle_snapshot(),
            "tokens": {
                k: v for k, v in state.items() if "token" in k and isinstance(v, (int, float))
            },
        }

    def _supplement_decision_explanations(self, state: Dict[str, Any]) -> None:
        """Optionally let the LLM explain LLM-free deterministic decisions.

        The deterministic verdict and ``validation_reasoning`` stay
        authoritative; this only adds a user-facing ``llm_explanation`` to
        report-visible decisions (confirmed-by-proof findings, audit
        observations, evidence conflicts) so users can understand what the
        machine-shaped proof summary means.  Every failure path degrades to
        the plain deterministic text.
        """

        analysis_cfg = getattr(self.config, "analysis", None)
        if analysis_cfg is None or not bool(
            getattr(analysis_cfg, "llm_decision_explanation", True)
        ):
            return
        budget = int(getattr(analysis_cfg, "llm_decision_explanation_budget", 50) or 0)
        if budget <= 0:
            return
        llm_client = self._decision_explanation_llm_client()
        if llm_client is None:
            return
        try:
            stats = apply_decision_explanations(
                state,
                llm_client=llm_client,
                budget=budget,
                used=self._decision_explanations_used,
            )
        except Exception as exc:  # pragma: no cover - defensive: never break the scan
            logger.debug("Decision explanation pass failed: %s", exc)
            return
        self._decision_explanations_used += int(stats.get("explained", 0))
        if stats.get("explained") or stats.get("failed"):
            logger.info(
                "Decision explanation pass: %d candidate(s), %d explained, "
                "%d failed, %d deferred by budget.",
                stats.get("candidates", 0),
                stats.get("explained", 0),
                stats.get("failed", 0),
                stats.get("skipped_budget", 0),
            )
        previous = state.get("decision_explanations")
        previous = previous if isinstance(previous, dict) else {}
        state["decision_explanations"] = {
            key: int(previous.get(key, 0) or 0) + int(stats.get(key, 0) or 0)
            for key in ("candidates", "explained", "skipped_budget", "failed")
        }

    def _decision_explanation_llm_client(self) -> Optional[LLMClient]:
        """Resolve the validation-role LLM client for decision explanations."""

        profiles = getattr(getattr(self.config, "scan", None), "llm_profiles", None)
        configured_ref = str(getattr(profiles, "validation", "") or "")
        clients = self.llm_clients or {}
        if configured_ref:
            client = clients.get(configured_ref)
            if client is not None:
                return client
        return clients.get("default")

    def _coalesce_validation_groups(
        self,
        issues: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Select one representative for each semantic validation group."""

        clustered: Dict[str, List[Dict[str, Any]]] = {}
        legacy: List[Dict[str, Any]] = []
        for issue in issues:
            cluster_uid = str(issue.get("validation_cluster_uid") or "")
            if cluster_uid:
                clustered.setdefault(cluster_uid, []).append(issue)
            else:
                legacy.append(issue)

        result: List[Dict[str, Any]] = []
        completeness_rank = {"complete": 3, "partial": 2, "unknown": 1}
        for cluster_uid in sorted(clustered):
            group = clustered[cluster_uid]
            representative = max(
                group,
                key=lambda item: (
                    completeness_rank.get(
                        str(item.get("evidence_completeness") or "unknown"),
                        0,
                    ),
                    len(item.get("positive_evidence") or []),
                    len(item.get("negative_evidence") or []),
                    str(item.get("evidence_hash") or ""),
                ),
            )
            occurrence_uids: List[str] = []
            provenance_hashes: List[str] = []
            evidence_hashes: List[str] = []
            for item in group:
                for field, target in (
                    ("occurrence_uid", occurrence_uids),
                    ("provenance_hash", provenance_hashes),
                    ("evidence_hash", evidence_hashes),
                ):
                    value = str(item.get(field) or "")
                    if value and value not in target:
                        target.append(value)
                for value in item.get("occurrence_uids") or []:
                    text = str(value)
                    if text and text not in occurrence_uids:
                        occurrence_uids.append(text)
            representative["occurrence_uids"] = sorted(occurrence_uids)
            representative["occurrence_count"] = len(occurrence_uids) or 1
            representative["provenance_hashes"] = sorted(provenance_hashes)
            representative["evidence_hashes"] = sorted(evidence_hashes)
            representative["grouped_candidate_count"] = len(group)
            result.append(representative)

        result.extend(self.deduplicate_issues(legacy))
        return result

    def _validate_with_deadline(
        self,
        item: _PreparedValidation,
        *,
        parent_token: Optional[CancellationToken],
        validator_agent: Optional[Any] = None,
    ) -> _ValidationWorkerResult:
        soft_budget = self._validation_soft_budget_seconds()
        token = parent_token.child() if parent_token is not None else CancellationToken()
        started = time.monotonic()
        try:
            with bind_cancellation_token(token):
                token.raise_if_cancelled()
                result = self._validate_prepared_issue(
                    item,
                    validator_agent=validator_agent,
                )
                result.evidence_pack = dict(item.evidence_pack)
                token.raise_if_cancelled()
        except CancellationError:
            # validation_deadline_seconds is a soft observability budget.  Only
            # the inherited scan/entry token (including an explicit parent
            # deadline) is authoritative cancellation.
            raise
        elapsed = max(0.0, time.monotonic() - started)
        self._record_validation_budget(item, result, soft_budget, elapsed)
        return result

    @staticmethod
    def _cancel_validation_futures(futures: Any) -> None:
        for future in list(futures):
            if isinstance(future, Future) and not future.done():
                future.cancel()

    @staticmethod
    def _cancellation_poll_seconds(
        parent_token: Optional[CancellationToken],
    ) -> Optional[float]:
        if parent_token is None:
            return None
        remaining = parent_token.remaining_seconds()
        if remaining is None:
            return 0.05
        remaining_seconds = float(remaining)
        return max(0.0, min(0.05, remaining_seconds))

    def _validation_soft_budget_seconds(self) -> Optional[float]:
        analysis_cfg = getattr(self.config, "analysis", None)
        raw = getattr(analysis_cfg, "validation_deadline_seconds", 600.0)
        if raw is None:
            return None
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return 600.0
        return value if value > 0 else None

    def _deterministic_prevalidation_enabled(self) -> bool:
        return True

    def _attempt_dynamic_reproduction(self, issue: Dict[str, Any]) -> None:
        """Ask for an approved reproduction plan for this candidate.

        Default ``dynamic_reproduction_mode: off`` makes this a no-op and the
        issue is left untouched.  With the mode enabled but no approved plan
        source installed, the attempt is recorded as ``no_plan_available`` and
        the scan continues exactly as before; the capability never synthesizes a
        plan of its own.
        """

        try:
            policy = make_dynamic_reproduction_policy(self.config)
        except DynamicReproductionError as exc:
            # An unusable internal override must not fail a candidate's scan; it
            # is reported once and the capability stays inert.
            if not getattr(self, "_dynamic_reproduction_policy_warned", False):
                self._dynamic_reproduction_policy_warned = True
                logger.warning("dynamic reproduction policy unusable: %s", exc)
            return
        if not policy.enabled:
            return
        service = getattr(self, "reproduction_service", None)
        if service is not None:
            service.attempt(issue, policy)
        else:
            # A standalone runner must not borrow a process-global provider
            # installed by a different scan or project.
            attempt_dynamic_reproduction(issue, policy=policy, provider=lambda *_: None)

    @staticmethod
    def _record_validation_budget(
        item: _PreparedValidation,
        result: _ValidationWorkerResult,
        soft_budget: Optional[float],
        elapsed: float,
    ) -> None:
        duration = round(max(0.0, elapsed), 4)
        result.metadata["validation_duration_seconds"] = duration
        item.raw_issue["validation_duration_seconds"] = duration
        if soft_budget is None:
            return

        budget = round(max(0.0, soft_budget), 4)
        result.metadata["validation_soft_budget_seconds"] = budget
        item.raw_issue["validation_soft_budget_seconds"] = budget
        if elapsed <= soft_budget:
            return

        overrun = round(elapsed - soft_budget, 4)
        result.metadata["validation_soft_budget_overrun"] = 1
        result.metadata["validation_soft_budget_overrun_seconds"] = overrun
        item.raw_issue["validation_soft_budget_overrun"] = True
        item.raw_issue["validation_soft_budget_overrun_seconds"] = overrun
        logger.warning(
            "Validation soft budget exceeded for issue %s in function %s: "
            "elapsed=%.3fs budget=%.3fs overrun=%.3fs; result retained.",
            item.raw_issue.get("id"),
            item.issue_func,
            elapsed,
            soft_budget,
            elapsed - soft_budget,
        )

    def _validation_worker_count(self, issue_count: int) -> int:
        if issue_count <= 1:
            return 1
        return max(
            1,
            min(issue_count, int(self.config.concurrency.validator_workers)),
        )

    def _assign_v3_investigation_budget(
        self,
        prepared: List[_PreparedValidation],
    ) -> List[_PreparedValidation]:
        depth = self._scan_depth()
        if depth not in {"balanced", "deep"} or not prepared:
            return prepared
        # Plan Phase 4 escalation rung R2: the V3 reattempt participates only
        # when ``runtime.analysis.validation_v3_reattempt`` is enabled.  The
        # flag defaults to True (the balanced pipeline has always run the V3
        # reattempt); only an explicit False yields the R1-only reference.
        analysis_cfg = getattr(self.config, "analysis", None)
        if analysis_cfg is not None and not getattr(analysis_cfg, "validation_v3_reattempt", True):
            return [replace(item, allow_v3=False, v3_max_iterations=0) for item in prepared]
        eligible = []
        for item in prepared:
            issue = item.raw_issue
            severity = str(issue.get("impact_level") or issue.get("severity") or "").lower()
            externally_reachable = self._externally_reachable(item)
            valid_obligation = self._has_valid_security_obligation(issue)
            closable_gap = self._has_readonly_closable_gap(issue)
            shadow_only = self._is_shadow_only_candidate(issue)
            selected = False
            reason = "not_selected"
            if shadow_only:
                reason = "shadow_only"
            elif depth == "deep":
                selected = True
                reason = "deep_all_unclosed_without_counterproof"
            elif not (self._v3_is_high_or_critical(item) or externally_reachable):
                reason = "balanced_risk_and_reachability_gate"
            elif not valid_obligation:
                reason = "missing_security_obligation"
            elif not closable_gap:
                reason = "no_readonly_closable_gap"
            else:
                selected = True
                reason = "balanced_high_critical_or_external"
            issue["validator_v3_eligibility"] = {
                "eligible": selected,
                "depth": depth,
                "reason": reason,
                "severity": severity or "unknown",
                "risk_score": self._v3_risk_score(item),
                "externally_reachable": externally_reachable,
                "valid_security_obligation": valid_obligation,
                "readonly_closable_gap": closable_gap,
                "required_fact_kinds": list(
                    EvidenceCompletionQueue.required_resolution_fact_kinds(
                        issue,
                        {"verdict": "uncertain"},
                    )
                ),
            }
            if not selected:
                continue
            eligible.append(item)
        selected_ids = {id(item) for item in eligible}
        return [
            replace(
                item,
                allow_v3=id(item) in selected_ids,
                v3_max_iterations=50 if id(item) in selected_ids else 0,
            )
            for item in prepared
        ]

    def _scan_depth(self) -> str:
        scan = getattr(self.config, "scan", None)
        raw = scan.get("depth") if isinstance(scan, dict) else getattr(scan, "depth", None)
        return str(raw or "fast").strip().lower()

    @staticmethod
    def _v3_risk_score(item: _PreparedValidation) -> int:
        issue = item.raw_issue
        try:
            explicit = int(issue.get("risk_score") or issue.get("priority_score") or 0)
        except (TypeError, ValueError):
            explicit = 0
        severity = str(issue.get("impact_level") or issue.get("severity") or "").lower()
        severity_score = {"critical": 100, "high": 80, "medium": 60}.get(severity, 0)
        return max(explicit, severity_score)

    @staticmethod
    def _v3_is_high_or_critical(item: _PreparedValidation) -> bool:
        issue = item.raw_issue
        severity = str(issue.get("impact_level") or issue.get("severity") or "").lower()
        return severity in {"high", "critical"}

    @staticmethod
    def _is_shadow_only_candidate(issue: Dict[str, Any]) -> bool:
        if str(issue.get("rollout_visibility") or "").lower() != "shadow":
            return False
        attribution = issue.get("attribution")
        sources = attribution.get("discovered_by") if isinstance(attribution, dict) else []
        normalized = {
            str(value).strip().lower()
            for value in (sources if isinstance(sources, list) else [])
            if str(value).strip()
        }
        if ValidationPipeline._is_conditional_snapshot_shadow(issue):
            return True
        return normalized == {"llm_active_discovery"} or (
            not normalized
            and str(issue.get("candidate_source") or "").lower() == "active_discovery"
        )

    @staticmethod
    def _has_valid_security_obligation(issue: Dict[str, Any]) -> bool:
        obligation = issue.get("security_obligation")
        return bool(
            isinstance(obligation, dict)
            and str(obligation.get("obligation_uid") or issue.get("obligation_uid") or "")
            and str(
                obligation.get("subject_uid")
                or issue.get("resource_identity")
                or issue.get("source_identity")
                or ""
            )
        )

    @staticmethod
    def _has_readonly_closable_gap(issue: Dict[str, Any]) -> bool:
        # A complete obligation may still need an auditable second decision
        # because V1 was uncertain or its verified score did not promote.  In
        # that case repository code/semantic tools can add decision evidence.
        if issue.get("candidate_promotion_eligible") is True:
            return True
        return bool(
            EvidenceCompletionQueue.required_resolution_fact_kinds(
                issue,
                {"verdict": "uncertain"},
            )
        )

    @staticmethod
    def _externally_reachable(item: _PreparedValidation) -> bool:
        issue = item.raw_issue
        entry = item.evidence_pack.get("entry_context")
        entry = entry if isinstance(entry, dict) else {}
        return bool(
            issue.get("externally_reachable")
            or issue.get("reachable_from_entry")
            or entry.get("entry_is_external_root")
            or entry.get("reachable_from_entry")
        )

    def _mark_unvalidated(self, state: Dict[str, Any], new_issues: List[Dict[str, Any]]) -> None:
        logger.info("Validator agent disabled, marking %d issue(s) unvalidated.", len(new_issues))
        for raw_issue in new_issues:
            self._ensure_discovery_attribution(raw_issue)
            issue_func = self._issue_function(raw_issue, state)
            decision = self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
            if decision:
                if decision.report_bucket:
                    state[decision.report_bucket].append(raw_issue)
                self._update_candidate_ledger(state, raw_issue)
                continue
            self._refresh_protocol_assessment(raw_issue)
            score_data = self.validation_pipeline.score_components(raw_issue, {})
            from .protocol_assessment import is_protocol_candidate

            outcome = (
                self.validation_pipeline.apply_deterministic_prevalidation(raw_issue, score_data)
                if is_protocol_candidate(raw_issue)
                else None
            ) or self.validation_pipeline.apply_unvalidated(raw_issue, score_data)
            if is_protocol_candidate(raw_issue):
                raw_issue["policy_disposition"] = raw_issue["candidate_disposition"]
            if outcome.report_bucket:
                state[outcome.report_bucket].append(raw_issue)
            self._update_candidate_ledger(state, raw_issue)

    def _prepare_issue_for_validation(
        self,
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        index: int,
    ) -> Optional[_PreparedValidation]:
        self._require_current_inputs()
        self._ensure_discovery_attribution(raw_issue)
        issue_func = self._issue_function(raw_issue, state)
        logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)

        scoped_build = self._scoped_build_id
        # Check every identity the candidate actually carries: the issue field
        # and the evidence pack must not hide a conflicting receipt behind a
        # single preferred field.
        pack = _as_dict(raw_issue.get("evidence_pack"))
        carried_builds = {
            value
            for value in (
                str(raw_issue.get("build_context_id") or ""),
                str(pack.get("build_context_id") or ""),
            )
            if value
        }
        rejection: Dict[str, Any] | None = None
        if len(carried_builds) > 1:
            # Self-contradictory candidate identity: never authorizable.
            rejection = {
                "code": "candidate_build_conflict",
                "carried_build_context_ids": sorted(carried_builds),
            }
        elif scoped_build and carried_builds and scoped_build not in carried_builds:
            # The candidate carries another variant's compilation receipt.
            # It cannot be validated under this scope, and the scoped build
            # must not be stamped onto it to authorize validation.
            rejection = {
                "code": "candidate_build_mismatch",
                "scoped_build_context_id": scoped_build,
                "candidate_build_context_id": sorted(carried_builds)[0],
            }
        elif scoped_build and not carried_builds:
            # An identity-less candidate cannot borrow the scoped build as an
            # authorization label; it stays unvalidated and reserved for
            # review instead of running this variant's Validator.
            rejection = {
                "code": "candidate_build_missing",
                "scoped_build_context_id": scoped_build,
            }
        if rejection is not None:
            raw_issue["build_scope_rejection"] = rejection
            state["notes"].append(
                f"Issue {raw_issue.get('id')} was kept for review without validation: "
                f"{rejection['code']} ({sorted(carried_builds) or 'no build identity'})."
            )
            outcome = self.validation_pipeline.apply_validator_result(
                raw_issue,
                {
                    "reasoning": (
                        "候选携带的构建身份缺失、自相冲突或属于另一变体，不能在当前验证"
                        "作用域下验证；保留待复核。"
                    )
                },
                verdict="uncertain",
                score_data=self.validation_pipeline.score_components(raw_issue, {}),
            )
            if outcome.report_bucket:
                state[outcome.report_bucket].append(raw_issue)
            self._update_candidate_ledger(state, raw_issue)
            return None

        ledger = state.get("candidate_ledger")
        mark_running = getattr(ledger, "mark_validation_running", None)
        if callable(mark_running):
            mark_running(raw_issue)

        conditional = raw_issue.get("analysis_scope") == "conditional_source_branch"
        decision = (
            None
            if conditional
            else self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
        )
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
            self._update_candidate_ledger(state, raw_issue)
            return None

        issue_code = self._issue_code(issue_func, state)
        evidence_pack = self._build_evidence_pack(raw_issue, state, issue_code)
        # FP-suppression guards ride on the issue so deterministic proof
        # selection can honor them without reaching into scan config.
        raw_issue["demote_source_lifecycle_confirm"] = self._depth_scoped_flag(
            "validation_demote_source_lifecycle_confirm"
        )
        raw_issue["obligation_infunction_release_guard"] = self._depth_scoped_flag(
            "validation_obligation_infunction_release_guard"
        )
        # Canonical per-feature measurement flags (validation_*): mirror the
        # resolved tri-state values so downstream TP/FP attribution can slice
        # per feature without reaching into scan config.
        raw_issue["validation_demote_source_lifecycle_confirm"] = raw_issue[
            "demote_source_lifecycle_confirm"
        ]
        raw_issue["validation_obligation_infunction_release_guard"] = raw_issue[
            "obligation_infunction_release_guard"
        ]
        raw_issue["validation_uncertain_replay_review"] = self._depth_scoped_flag(
            "validation_uncertain_replay_review"
        )
        raw_issue["validation_checked_proofs"] = self._checked_proofs_enabled()
        if self._review_enabled():
            if raw_issue.pop("_review_restore_evidence", False) and raw_issue.get(
                "review_validation_evidence"
            ):
                evidence_pack = deepcopy(raw_issue["review_validation_evidence"])
                issue_code = str(raw_issue.get("review_function_context") or issue_code)
            raw_issue["review_validation_evidence"] = deepcopy(evidence_pack)
            raw_issue["review_function_context"] = issue_code
            raw_issue["review_checked_proofs_enabled"] = self._checked_proofs_enabled()
            checker = self._review_checker()
            checker.prepare(raw_issue)
            if raw_issue["review_checked_proofs_enabled"]:
                checker.check(raw_issue)
            self._review_checkpoint(raw_issue, "prepared")
        if conditional:
            outcome = self.validation_pipeline.apply_validator_result(
                raw_issue,
                {"reasoning": "条件风险尚无对应构建事实，保留待复核。"},
                verdict="uncertain",
                score_data=self.validation_pipeline.score_components(raw_issue, {}),
            )
            if outcome.report_bucket:
                state[outcome.report_bucket].append(raw_issue)
            self._update_candidate_ledger(state, raw_issue)
            return None
        # Controlled dynamic reproduction runs before deterministic prevalidation
        # so a qualified witness reaches the existing confirmation branch.  The
        # shipped default is off, in which case this returns immediately.
        self._attempt_dynamic_reproduction(raw_issue)
        if self._deterministic_prevalidation_enabled():
            self._evidence_completion_queue.complete_prevalidation(
                raw_issue,
                validation_evidence=evidence_pack,
            )
            deterministic_outcome = self.validation_pipeline.apply_deterministic_prevalidation(
                raw_issue,
                self.validation_pipeline.score_components(raw_issue, {}),
            )
            if deterministic_outcome is not None:
                self._require_current_inputs()
                self._record_deterministic_prevalidation_outcome(
                    state,
                    raw_issue,
                    deterministic_outcome,
                )
                if deterministic_outcome.report_bucket:
                    state[deterministic_outcome.report_bucket].append(raw_issue)
                if deterministic_outcome.memory_status:
                    self.remember_validation_result(
                        raw_issue,
                        deterministic_outcome.memory_status,
                    )
                self._update_candidate_ledger(state, raw_issue)
                # The candidate's own adjudication is complete, so the
                # reproduction capabilities created for it are retired here
                # instead of being left live for the rest of the process.
                release_issue_dynamic_reproduction_authority(raw_issue)
                return None
        return _PreparedValidation(
            index=index,
            raw_issue=raw_issue,
            issue_func=issue_func,
            issue_code=issue_code,
            evidence_pack=evidence_pack,
        )

    @staticmethod
    def _ensure_discovery_attribution(issue: Dict[str, Any]) -> None:
        attribution = issue.get("attribution")
        if not isinstance(attribution, dict):
            attribution = {
                "schema_version": "zscope.finding-attribution.v1",
                "discovered_by": [],
                "discovery_details": [],
                "decided_by": "unresolved",
                "decision_level": "none",
            }
            issue["attribution"] = attribution
        existing = attribution.get("discovered_by")
        discovered = set(existing if isinstance(existing, list) else [])
        pack = _as_dict(issue.get("evidence_pack"))
        raw_sources = [
            issue.get("candidate_source"),
            issue.get("candidate_kind"),
            pack.get("candidate_source"),
            *(issue.get("evidence_sources") or []),
        ]
        sources = {str(value or "").strip().lower() for value in raw_sources if value}
        if any("active_discovery" in value or "llm_observation" in value for value in sources):
            discovered.add("llm_active_discovery")
        if any(
            "backend_signal" in value or value.startswith(("svf", "saber", "joern"))
            for value in sources
        ):
            discovered.add("backend_signal")
        if (
            issue.get("rule")
            or issue.get("rule_id")
            or any(
                value in {"deterministic_rule", "clang_ast_cfg", "graph", "project_fact_pass"}
                or value.startswith(("clang_", "cpp_", "java_local"))
                for value in sources
            )
        ):
            discovered.add("deterministic_rule")
        attribution["discovered_by"] = sorted(discovered)
        details = attribution.get("discovery_details")
        if not isinstance(details, list):
            details = []
        known = {
            (str(item.get("kind") or ""), str(item.get("source_id") or ""))
            for item in details
            if isinstance(item, dict)
        }
        for kind in sorted(discovered):
            source_id = ",".join(sorted(sources))[:500]
            if (kind, source_id) not in known:
                details.append({"kind": kind, "source_id": source_id})
        attribution["discovery_details"] = details

    def _validate_prepared_issue(
        self,
        item: _PreparedValidation,
        *,
        validator_agent: Optional[Any] = None,
    ) -> _ValidationWorkerResult:
        cache_key = ""
        cache_owner = False
        try:
            # Projection establishes completeness even on a cached verdict.
            val_input = self._validator_input(item.raw_issue, item.issue_code, item.evidence_pack)
            cache_key = self._validator_cache_key(item)
            cached = self._validator_cache_get(cache_key)
            if cached is not None:
                metadata = self._empty_token_metadata()
                metadata["validator_cache_hit"] = 1
                return _ValidationWorkerResult(
                    index=item.index,
                    raw_issue=item.raw_issue,
                    issue_func=item.issue_func,
                    success=True,
                    val_data=dict(cached),
                    metadata=metadata,
                )
            if cache_key:
                cache_owner = self._validator_result_cache.reserve(cache_key)
                if not cache_owner:
                    cached = self._validator_result_cache.wait(
                        cache_key,
                        timeout=self._validation_cache_wait_seconds(),
                    )
                    if cached is not None:
                        self._require_current_inputs()
                        metadata = self._empty_token_metadata()
                        metadata["validator_cache_hit"] = 1
                        metadata["validator_inflight_coalesced"] = 1
                        return _ValidationWorkerResult(
                            index=item.index,
                            raw_issue=item.raw_issue,
                            issue_func=item.issue_func,
                            success=True,
                            val_data=dict(cached),
                            metadata=metadata,
                        )
                    cache_owner = self._validator_result_cache.reserve(cache_key)
            validator_agent = validator_agent or self._build_validator_agent()
            token_metadata = self._empty_token_metadata()
            val_resp = validator_agent.run(val_input)
            self._merge_response_metadata(token_metadata, getattr(val_resp, "metadata", {}) or {})

            if not val_resp.success:
                if not item.allow_v3 or not self._recoverable_v1_failure(val_resp):
                    return _ValidationWorkerResult(
                        index=item.index,
                        raw_issue=item.raw_issue,
                        issue_func=item.issue_func,
                        success=False,
                        error=val_resp.error,
                        metadata=token_metadata,
                    )
                stop_reason = (
                    "output_truncated"
                    if "truncat" in str(val_resp.error or "").lower()
                    else "malformed_output"
                )
                val_data = self._terminal_uncertain_v3_result(
                    item,
                    {},
                    validation_pass="initial",
                    stop_reason=stop_reason,
                    reasoning=("初始结构化结果可恢复地无效；定向排查或可基于证据重建该决策。"),
                )
                item.raw_issue["validator_v1_recoverable_error"] = str(val_resp.error or "")[:500]
            else:
                val_data = self._normalize_worker_response(
                    item,
                    validator_agent,
                    val_resp.data,
                    token_metadata,
                )
            if self._review_enabled():
                item.raw_issue.setdefault("review_prior_results", []).append(deepcopy(val_data))
                self._review_checkpoint(item.raw_issue, "after_v1")
            val_data = self._run_v3_evidence_recheck(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
            if self._review_enabled():
                item.raw_issue.setdefault("review_prior_results", []).append(deepcopy(val_data))
                self._review_checkpoint(item.raw_issue, "after_v2")
            val_data = self._run_v3_targeted_investigation(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
            val_data = self._run_v2b_adjudication(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
            val_data = self._context_checked_result(item.raw_issue, val_data)
            if self._validator_cache_put(cache_key, val_data):
                cache_owner = False
            return _ValidationWorkerResult(
                index=item.index,
                raw_issue=item.raw_issue,
                issue_func=item.issue_func,
                success=True,
                val_data=val_data,
                metadata=token_metadata,
                evidence_pack=item.evidence_pack,
            )
        finally:
            if cache_owner and cache_key:
                self._validator_result_cache.abandon(cache_key)
            self._close_thread_llm_sessions()

    @staticmethod
    def _recoverable_v1_failure(response: Any) -> bool:
        error = str(getattr(response, "error", "") or "").lower()
        metadata = getattr(response, "metadata", {}) or {}
        return bool(
            any(token in error for token in ("malformed", "parse", "schema", "truncat", "json"))
            or metadata.get("snapshot_terminal_tool_failed")
            or metadata.get("validator_protocol_exhausted")
            or str(metadata.get("finish_reason") or "").lower() == "length"
        )

    def _validator_cache_get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        self._require_current_inputs()
        cached = self._validator_result_cache.get(cache_key)
        if cached is not None:
            if self._validator_result_is_cacheable(cached):
                self._require_current_inputs()
                return cached
            self._validator_result_cache.discard(cache_key)
        loader = getattr(self.snapshot_store, "load_validation_result", None)
        if not callable(loader) or not cache_key:
            return None
        try:
            cached = loader(
                cache_key,
                protocol=self._VALIDATION_CACHE_PROTOCOL,
                candidate_schema_version=CANDIDATE_SCHEMA_VERSION,
                environment_fingerprint=self._validation_environment_fingerprint,
            )
        except Exception:
            logger.exception(
                "Persistent validation cache read failed for %s.",
                cache_key,
            )
            return None
        if isinstance(cached, dict) and self._validator_result_is_cacheable(cached):
            self._require_current_inputs()
            self._validator_result_cache.put(cache_key, cached)
            return dict(cached)
        return None

    def _validator_cache_put(self, cache_key: str, val_data: Dict[str, Any]) -> bool:
        self._require_current_inputs()
        if (
            not cache_key
            or not isinstance(val_data, dict)
            or not self._validator_result_is_cacheable(val_data)
        ):
            return False
        self._validator_result_cache.put(cache_key, val_data)
        saver = getattr(self.snapshot_store, "save_validation_result", None)
        if not callable(saver):
            return True
        try:
            saver(
                cache_key,
                val_data,
                protocol=self._VALIDATION_CACHE_PROTOCOL,
                candidate_schema_version=CANDIDATE_SCHEMA_VERSION,
                environment_fingerprint=self._validation_environment_fingerprint,
                max_entries=max(1, self._validator_result_cache_size * 2),
            )
        except Exception:
            logger.exception(
                "Persistent validation cache write failed for %s.",
                cache_key,
            )
        return True

    @classmethod
    def _validator_result_is_cacheable(cls, val_data: Dict[str, Any]) -> bool:
        if str(val_data.get("schema_version") or "") != VALIDATOR_RESULT_VERSION:
            return True
        # A V3 terminal is authoritative only together with the cited
        # tool-backed fact records attached to the issue.  The legacy result
        # cache stores only ValidatorResult, so caching it would drop the
        # promotion evidence on replay.
        if str(val_data.get("pass") or "") == "investigation_synthesis":
            return False
        stop_reason = str(val_data.get("stop_reason") or "").strip().lower()
        return stop_reason not in cls._TRANSIENT_VALIDATOR_STOP_REASONS

    def _validation_cache_wait_seconds(self) -> Optional[float]:
        analysis_cfg = getattr(self.config, "analysis", None)
        raw = getattr(analysis_cfg, "validation_deadline_seconds", 600)
        if raw is None:
            return None
        try:
            return max(1.0, float(raw))
        except (TypeError, ValueError):
            return 600.0

    @staticmethod
    def _project_knowledge_cache_identity(pack: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        knowledge = _as_dict(pack.get("project_knowledge"))
        if not knowledge:
            # Preserve the pre-Wiki cache branch exactly when mode is off or
            # shadow context was intentionally not injected.
            return None
        selection = _as_dict(knowledge.get("selection"))
        return {
            "schema_version": knowledge.get("schema_version"),
            "resolution_mode": knowledge.get("resolution_mode"),
            "wiki_revision_id": knowledge.get("wiki_revision_id"),
            "source_manifest_digest": knowledge.get("source_manifest_digest"),
            "context_digest": knowledge.get("context_digest"),
            "ranking_version": selection.get("ranking_version"),
        }

    def _validator_cache_key(self, item: _PreparedValidation) -> str:
        if self._review_enabled():
            # Review receipts and investigation deltas are candidate-bound.
            return ""
        issue = item.raw_issue
        prepared_pack = getattr(item, "evidence_pack", None)
        pack = (
            prepared_pack
            if isinstance(prepared_pack, dict)
            else _as_dict(issue.get("evidence_pack"))
        )
        # Display IDs (for example ISSUE_1) are presentation-only and may
        # collide across entries.  Only the content-derived v3 identity can be
        # used directly; otherwise build the key from structured evidence.
        stable_id = issue.get("candidate_uid") or pack.get("candidate_uid")
        validation_cluster_uid = issue.get("validation_cluster_uid") or pack.get(
            "validation_cluster_uid"
        )
        project_knowledge_identity = self._project_knowledge_cache_identity(pack)
        review_memory_identity = self._review_memory_cache_identity()
        # v3's cluster identity already includes the project revision, root
        # cause, decision-changing code/evidence, and validator contract.
        # Adding occurrence-local function/location/source fields here defeats
        # cross-entry in-flight coalescing and revalidates the same obligation.
        if validation_cluster_uid:
            payload = {
                "protocol": self._VALIDATION_CACHE_PROTOCOL,
                "decision_context_version": DECISION_CONTEXT_VERSION,
                "environment": self._validation_environment_fingerprint,
                "validation_cluster_uid": validation_cluster_uid,
                "build_context_id": issue_build_context_id(issue),
            }
            if issue.get("protocol_assessment"):
                payload["protocol_assessment"] = self._stable_hash(issue["protocol_assessment"])
            if project_knowledge_identity is not None:
                payload["project_knowledge"] = project_knowledge_identity
            if review_memory_identity is not None:
                payload["review_memory"] = review_memory_identity
            stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
            return hashlib.sha256(stable.encode("utf-8")).hexdigest()
        source_value = issue.get("source") or pack.get("source")
        sink_value = issue.get("sink") or pack.get("sink")
        resource_value = (
            issue.get("resource_signature")
            or issue.get("resource")
            or pack.get("resource_signature")
            or pack.get("resource")
            or issue.get("defect_class")
            or issue.get("category")
            or pack.get("defect_class")
        )
        if not stable_id and not validation_cluster_uid:
            source_text = self._cache_component_text(source_value)
            sink_text = self._cache_component_text(sink_value)
            resource_text = self._cache_component_text(resource_value)
            if not (
                (source_text or sink_text)
                and resource_text
                and (issue.get("function") or item.issue_func)
                and (issue.get("defect_class") or issue.get("category") or pack.get("defect_class"))
            ):
                return ""
        payload = {
            "protocol": self._VALIDATION_CACHE_PROTOCOL,
            "build_context_id": issue_build_context_id(issue),
            "semantic_contract_version": issue.get("semantic_contract_version")
            or pack.get("semantic_contract_version")
            or "",
            "evidence_slice_version": VALIDATOR_EVIDENCE_SLICE_V3,
            "decision_context_version": DECISION_CONTEXT_VERSION,
            "environment": self._validation_environment_fingerprint,
            "validation_cluster_uid": validation_cluster_uid,
            "candidate_uid": stable_id,
            "category": issue.get("defect_class")
            or issue.get("category")
            or pack.get("defect_class"),
            "function": issue.get("function") or item.issue_func,
            "location": issue.get("location"),
            "source": source_value,
            "sink": sink_value,
            "resource": resource_value,
            "code_hash": self._stable_hash(getattr(item, "issue_code", "")),
            "decision_evidence_hash": (
                issue.get("decision_evidence_hash")
                or pack.get("decision_evidence_hash")
                or issue.get("evidence_hash")
                or pack.get("evidence_hash")
                or self._stable_hash(pack)
            ),
            "prompt_hash": issue.get("prompt_hash") or pack.get("prompt_hash"),
        }
        if issue.get("protocol_assessment"):
            payload["protocol_assessment"] = self._stable_hash(issue["protocol_assessment"])
        if project_knowledge_identity is not None:
            payload["project_knowledge"] = project_knowledge_identity
        if review_memory_identity is not None:
            payload["review_memory"] = review_memory_identity
        stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    def _review_memory_cache_identity(self) -> Optional[Dict[str, Any]]:
        project = getattr(self.config, "project", None)
        settings = getattr(project, "review_memory", None)
        if project is None or settings is None or getattr(settings, "mode", "off") != "active":
            return None
        try:
            from ...review_memory.store import ReviewMemoryStore

            project_key = str(getattr(project, "project_id", "") or project.project_root)
            store = ReviewMemoryStore(project.project_root, settings.state_dir)
            active = store.active_pointer()
            return {
                "schema_version": "zscope.validator-review-memory.v1",
                "project_id": project_key,
                "revision": active.get("revision"),
                "digest": active.get("digest"),
                "pattern_ids": active.get("pattern_ids", []),
            }
        except Exception:
            return {"schema_version": "zscope.validator-review-memory.v1", "unavailable": True}

    def _configured_entry_identity(self) -> str:
        project_cfg = getattr(self.config, "project", None)
        if project_cfg is None:
            return ""
        function_name = str(getattr(project_cfg, "entry_function", "") or "")
        if not function_name:
            return ""
        return FunctionEntry(
            function_name=function_name,
            file_path=str(getattr(project_cfg, "entry_file_path", "") or "") or None,
            signature=str(getattr(project_cfg, "entry_signature", "") or "") or None,
        ).identity_key(getattr(project_cfg, "project_root", None))

    def _validation_cache_size(self) -> int:
        analysis_cfg = getattr(self.config, "analysis", None)
        raw = getattr(analysis_cfg, "validation_cache_entries", self._DEFAULT_VALIDATION_CACHE_SIZE)
        if raw is None:
            return 0
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            return self._DEFAULT_VALIDATION_CACHE_SIZE

    def _build_validation_environment_fingerprint(self) -> str:
        project_cfg = getattr(self.config, "project", None)
        project_root = Path(getattr(project_cfg, "project_root", ".") or ".")
        validator_cfg = next(
            (
                agent
                for agent in (getattr(project_cfg, "agents", None) or [])
                if getattr(agent, "name", "") == "validator_agent"
            ),
            None,
        )
        profiles = getattr(getattr(self.config, "scan", None), "llm_profiles", None)
        llm_ref = str(getattr(profiles, "validation", "") or "")
        if not llm_ref:
            llm_ref = str(getattr(validator_cfg, "llm_ref", "") or "default")
        client = self.llm_clients.get(llm_ref) or self.llm_clients.get("default")
        payload = {
            "protocol": self._VALIDATION_CACHE_PROTOCOL,
            "decision_context_version": DECISION_CONTEXT_VERSION,
            "instance_scope": {
                "build_context_id": self._scoped_build_id,
                "usr": self._scoped_usr,
                "semantics_digest": getattr(self, "_instance_semantics_digest", ""),
            },
            "project_root": project_root.resolve().as_posix(),
            "project_revision": self._project_revision(project_root),
            "index_epoch": self._index_epoch(),
            "validator_llm_ref": llm_ref,
            "llm_client": self._llm_identity(client),
            "validator_contract": getattr(validator_cfg, "contract", None),
            "validator_prompt_version": getattr(validator_cfg, "prompt_version", None),
            "tool_policy": self._tool_policy_identity(),
            "effective_rules_sha256": self._effective_rules_sha256(),
        }
        return self._stable_hash(payload)

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

    def _index_epoch(self) -> Any:
        for name in (
            "knowledge_epoch",
            "index_epoch",
            "source_fingerprint",
            "revision",
        ):
            value = getattr(self.code_index, name, None)
            if callable(value):
                try:
                    value = value()
                except Exception:
                    value = None
            if value not in (None, ""):
                return value
        backend = getattr(self.code_index, "backend", None)
        return {
            "backend": type(backend).__name__ if backend is not None else "regex",
            "configured_backend": getattr(self.code_index, "backend_name", None),
        }

    def _tool_policy_identity(self) -> Dict[str, Any]:
        try:
            policy = self.tool_policy_for_agent("validator_agent")
        except Exception:
            policy = None
        if policy is None:
            return {}
        if hasattr(policy, "__dict__"):
            values = {
                key: value
                for key, value in vars(policy).items()
                if not key.lower().endswith(("token", "secret", "key", "password"))
            }
            return {"type": type(policy).__name__, "values": values}
        return {"type": type(policy).__name__, "value": str(policy)}

    @staticmethod
    def _llm_identity(client: Any) -> Dict[str, Any]:
        if client is None:
            return {}
        identity: Dict[str, Any] = {"type": type(client).__name__}
        for name in ("models", "model", "supports_structured_output", "max_tokens"):
            value = getattr(client, name, None)
            if value not in (None, ""):
                identity[name] = value
        return identity

    @staticmethod
    def _project_revision(project_root: Path) -> str:
        """Read the worktree revision without invoking git for every candidate."""
        git_dir = project_root / ".git"
        try:
            if git_dir.is_file():
                marker = git_dir.read_text(encoding="utf-8", errors="replace").strip()
                if marker.lower().startswith("gitdir:"):
                    candidate = Path(marker.split(":", 1)[1].strip())
                    git_dir = candidate if candidate.is_absolute() else (project_root / candidate)
            head = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
            if head.startswith("ref:"):
                ref_path = git_dir / head.split(":", 1)[1].strip()
                return ref_path.read_text(encoding="utf-8", errors="replace").strip()
            return head
        except OSError:
            return ""

    @staticmethod
    def _stable_hash(value: Any) -> str:
        stable = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    @staticmethod
    def _cache_component_text(value: Any) -> str:
        if isinstance(value, dict):
            return " ".join(
                ValidationRunner._cache_component_text(item) for item in value.values()
            ).strip()
        if isinstance(value, list):
            return " ".join(ValidationRunner._cache_component_text(item) for item in value).strip()
        if value is None:
            return ""
        return str(value).strip()

    def _close_thread_llm_sessions(self) -> None:
        seen: set[int] = set()
        for client in self.llm_clients.values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_thread_session = getattr(client, "close_thread_session", None)
            if callable(close_thread_session):
                close_thread_session()

    def _apply_validation_worker_result(
        self,
        state: Dict[str, Any],
        result: _ValidationWorkerResult,
    ) -> None:
        self._require_current_inputs()
        self._accumulate_token_metadata(state, result.metadata)
        raw_issue = result.raw_issue
        from .protocol_assessment import feedback_changed

        if feedback_changed(raw_issue):
            self._refresh_protocol_assessment(raw_issue)
        if not result.success:
            self._handle_validation_failure(state, raw_issue, result.issue_func, result.error)
            self._update_candidate_ledger(state, raw_issue)
            release_issue_dynamic_reproduction_authority(raw_issue)
            return

        val_data = self._context_checked_result(raw_issue, result.val_data)
        if self._review_enabled():
            raw_issue["review_latest_result"] = deepcopy(val_data)
        self._attach_validator_missing_fact_request(raw_issue, val_data)
        verdict = validation_verdict(val_data)
        raw_issue["model_verdict"] = verdict
        raw_issue["validator_result_pass"] = str(val_data.get("pass") or "initial")
        if str(val_data.get("schema_version") or "") == VALIDATOR_RESULT_VERSION:
            raw_issue["validator_stop_reason"] = str(val_data.get("stop_reason") or "")
        score_data = self.validation_pipeline.score_components(raw_issue, val_data)
        outcome = self.validation_pipeline.apply_validator_result(
            raw_issue,
            val_data,
            verdict=verdict,
            score_data=score_data,
        )
        if (
            outcome.memory_status == "needs_review"
            and str(val_data.get("schema_version") or "") != "zscope.validator-result.v3"
        ):
            completion = self._evidence_completion_queue.complete(
                raw_issue,
                validator_data={**val_data, "verdict": verdict},
                validation_evidence=result.evidence_pack,
            )
            if completion is not None:
                state.setdefault("evidence_completion_requests", []).append(
                    {
                        "validation_cluster_uid": completion.validation_cluster_uid,
                        "missing_fact": completion.missing_fact,
                        "reason": completion.reason,
                        "status": raw_issue.get("evidence_completion_status"),
                    }
                )
                # Legacy v2 replay compatibility. New v3 sessions resolve a
                # typed fact and, when it adds partial evidence, run V2 before
                # reaching this policy layer.
                if raw_issue.get("evidence_completion_status") == "completed":
                    outcome = self.validation_pipeline.apply_validator_result(
                        raw_issue,
                        val_data,
                        verdict=verdict,
                        score_data=score_data,
                    )
        raw_issue["policy_disposition"] = str(
            raw_issue.get("candidate_disposition") or outcome.memory_status or "needs_review"
        )
        self._record_validator_attribution(raw_issue, val_data, outcome)
        self._require_current_inputs()
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)
        if outcome.memory_status:
            self.remember_validation_result(raw_issue, outcome.memory_status)
        self._update_candidate_ledger(state, raw_issue)
        self._log_validation_outcome(raw_issue, val_data, verdict, outcome.final_score)
        # Every consumer of this candidate's confirmation capability (the
        # deterministic pre-pass and the validator-result adjudication above) has
        # run, so the plan-scoped authority is released with the candidate.
        release_issue_dynamic_reproduction_authority(raw_issue)

    @staticmethod
    def _context_checked_result(issue: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        if (
            issue.get("validator_context_requires_retrieval")
            and issue.get("decision_fact_coverage") != "complete"
            and not _as_dict(issue.get("v3_evidence_closure")).get("complete")
        ):
            issue.setdefault("model_verdict_before_context_check", validation_verdict(result))
            issue["validation_context_incomplete"] = True
            return {**result, "verdict": "uncertain"}
        issue.pop("validation_context_incomplete", None)
        return result

    @staticmethod
    def _evidence_completeness_from_issue(issue: Dict[str, Any]) -> str:
        """Derive the report-level ``evidence_completeness`` signal.

        The scan-time envelope can only emit ``unknown`` because validation
        has not run yet.  Once the fact slice and completion outcome exist,
        the field carries the real coverage so downstream metrics stop
        reading a constant (plan Phase 2.2 production-chain fix).
        """

        if issue.get("validation_context_incomplete"):
            return "partial"
        coverage = str(issue.get("decision_fact_coverage") or "").strip().lower()
        if coverage in {"complete", "partial"}:
            return coverage
        status = str(issue.get("evidence_completion_status") or "").strip().lower()
        if status in {"completed", "completed_with_proof", "completed_partial"}:
            return "partial" if status == "completed_partial" else "complete"
        return "unknown"

    @staticmethod
    def _record_validator_attribution(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        outcome: ValidationOutcome,
    ) -> None:
        attribution = issue.get("attribution")
        if not isinstance(attribution, dict):
            attribution = {
                "schema_version": "zscope.finding-attribution.v1",
                "discovered_by": [],
                "discovery_details": [],
            }
            issue["attribution"] = attribution
        policy_disposition = str(
            issue.get("candidate_disposition") or outcome.memory_status or "needs_review"
        )
        if (
            issue.get("decision_proof") and issue.get("proof_coverage") == "complete"
        ) or policy_disposition == "rejected_with_proof":
            attribution["decided_by"] = "deterministic_proof"
        elif policy_disposition in {"confirmed", "validated"}:
            attribution["decided_by"] = "validator_llm"
        else:
            # A model attempt is not itself a final decision.  In particular,
            # rejected/uncertain output without a deterministic contradiction
            # remains an unresolved, user-visible review obligation.
            attribution["decided_by"] = "unresolved"
        result_pass = str(val_data.get("pass") or "initial")
        attribution["decision_level"] = {
            "initial": "V1",
            "evidence_recheck": "V2",
            "investigation_synthesis": "V3",
        }.get(result_pass, "V1")
        if attribution["decided_by"] == "deterministic_proof":
            attribution["decision_level"] = "V0"
        # Escalation-rung observability: record the confirmation path for
        # confirmed findings (balanced_confirmed_tp_plan.md Phase 5).  Unset
        # for everything else so ``confirmed_via`` stays a confirmed-only key.
        if policy_disposition in {"confirmed", "validated"}:
            if attribution["decided_by"] == "deterministic_proof":
                confirmed_via = "deterministic_proof"
            elif str(issue.get("promotion_reason") or "") == "model_high_confidence_confirmation":
                confirmed_via = "high_confidence_band"
            else:
                confirmed_via = "validator_model"
            issue["confirmed_via"] = confirmed_via
            attribution["confirmed_via"] = confirmed_via
        issue["validator_policy_outcome"] = {
            "model_verdict": validation_verdict(val_data),
            "policy_disposition": policy_disposition,
            "decision_level": attribution["decision_level"],
        }
        issue["evidence_completeness"] = ValidationRunner._evidence_completeness_from_issue(issue)

    @staticmethod
    def _attach_validator_missing_fact_request(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> None:
        request = val_data.get("missing_fact_request")
        if not isinstance(request, dict):
            return
        fact_kind = str(request.get("fact_kind") or "").strip().lower()
        if fact_kind not in VALIDATOR_MISSING_FACT_KINDS:
            issue["validator_missing_fact_request_rejected"] = "unsupported_fact_kind"
            return
        existing = issue.get("missing_fact_kinds")
        values = [str(value) for value in existing] if isinstance(existing, list) else []
        if fact_kind not in values:
            values.append(fact_kind)
        issue["missing_fact_kinds"] = values
        issue["validator_missing_fact_request"] = {
            "fact_kind": fact_kind,
            "subject_uid": str(request.get("subject_uid") or ""),
            "function_uid": str(request.get("function_uid") or ""),
            "reason": str(request.get("reason") or ""),
        }

    def _update_candidate_ledger(
        self,
        state: Dict[str, Any],
        issue: Dict[str, Any],
    ) -> None:
        self._require_current_inputs()
        ledger = state.get("candidate_ledger")
        marker = getattr(ledger, "mark_issue_terminal", None)
        if not callable(marker):
            return
        disposition = str(issue.get("candidate_disposition") or "needs_review").lower()
        status = str(issue.get("validation_status") or issue.get("status") or disposition).lower()
        marker(issue, disposition=disposition, status=status)

    def _normalize_worker_response(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        if (
            is_entry_root_dead_code_rejection(val_data, item.evidence_pack)
            and not self._validator_evidence_slice_enabled()
        ):
            val_data = self._retry_entry_root_rejection_for_worker(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
        return val_data

    @staticmethod
    def _terminal_uncertain_v3_result(
        item: _PreparedValidation,
        prior: Dict[str, Any],
        *,
        validation_pass: str,
        stop_reason: str,
        reasoning: str,
    ) -> Dict[str, Any]:
        """Create one schema-valid runtime terminal without model coercions."""

        def identity(*values: Any, fallback: str) -> str:
            for value in values:
                if isinstance(value, str) and value.strip():
                    return value.strip()
            return fallback

        def evidence(field: str, *, limit: int, max_length: int) -> tuple[str, ...]:
            raw = prior.get(field)
            if not isinstance(raw, list):
                return ()
            result: list[str] = []
            for value in raw:
                if not isinstance(value, str) or not value.strip() or len(value) > max_length:
                    continue
                result.append(value.strip())
                if len(result) >= limit:
                    break
            return tuple(result)

        candidate_uid = identity(
            prior.get("candidate_uid"),
            item.raw_issue.get("candidate_uid"),
            item.raw_issue.get("candidate_id"),
            item.raw_issue.get("id"),
            fallback="unknown-candidate",
        )
        cluster_uid = identity(
            prior.get("validation_cluster_uid"),
            item.raw_issue.get("validation_cluster_uid"),
            fallback=f"validation:{candidate_uid}",
        )
        return ValidatorResultV3(
            candidate_uid=candidate_uid,
            validation_cluster_uid=cluster_uid,
            validation_pass=validation_pass,
            verdict="uncertain",
            reasoning=(reasoning.strip() or "Validator 在形成最终决策前已停止。")[:4000],
            positive_evidence=evidence("positive_evidence", limit=12, max_length=1000),
            negative_evidence=evidence("negative_evidence", limit=12, max_length=1000),
            evidence_refs=evidence("evidence_refs", limit=32, max_length=512),
            blocking_negative_evidence=(prior.get("blocking_negative_evidence") is True),
            missing_fact_request=None,
            stop_reason=stop_reason,
        ).to_dict()

    def _run_v3_evidence_recheck(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Resolve all obligation facts and run at most one stateless V2."""

        if str(val_data.get("schema_version") or "") != "zscope.validator-result.v3":
            return val_data
        item.raw_issue.setdefault("validator_pass_history", []).append(
            {
                "pass": str(val_data.get("pass") or "initial"),
                "verdict": validation_verdict(val_data),
                "stop_reason": str(val_data.get("stop_reason") or ""),
            }
        )
        try:
            batch = self._evidence_completion_queue.resolve_required_facts(
                item.raw_issue,
                validator_data=val_data,
                validation_evidence=item.evidence_pack,
            )
        except Exception as exc:
            logger.warning(
                "Required fact resolution failed for candidate %s: %s",
                item.raw_issue.get("candidate_uid") or item.raw_issue.get("id"),
                exc,
            )
            item.raw_issue["validator_fact_resolution"] = {
                "status": "provider_error",
                "error": f"{type(exc).__name__}: {exc}"[:500],
            }
            item.raw_issue["validator_v2_stop_reason"] = "unsupported_fact"
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                stop_reason="unsupported_fact",
                reasoning="所需的确定性事实提供方执行失败。",
            )

        statuses = [value.status for value in batch.resolutions]
        item.raw_issue["validator_fact_resolution"] = {
            "fact_kinds": [value.fact_kind for value in batch.resolutions],
            "statuses": statuses,
            "status": str(item.raw_issue.get("evidence_completion_status") or "not_applicable"),
            "evidence_delta_hash": batch.evidence_delta_hash,
            "proof_added": batch.proof_added,
        }
        token_metadata["validator_fact_resolution_count"] = int(
            token_metadata.get("validator_fact_resolution_count", 0) or 0
        ) + len(batch.resolutions)
        if batch.proof_added:
            token_metadata["validator_fact_resolution_proof_count"] = (
                int(token_metadata.get("validator_fact_resolution_proof_count", 0) or 0) + 1
            )
            item.raw_issue["validator_v2_stop_reason"] = "decision_complete"
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                stop_reason="decision_complete",
                reasoning=("必需的事实消解已产出完整的确定性证明；最终处置由策略层决定。"),
            )

        if not batch.has_evidence_delta:
            stop_reason = (
                "fact_timeout"
                if "timeout" in statuses
                else (
                    "unsupported_fact"
                    if any(value in {"unsupported", "provider_error"} for value in statuses)
                    else (
                        "duplicate_fact_request"
                        if statuses and all(value == "duplicate_request" for value in statuses)
                        else "no_evidence_gain"
                    )
                )
            )
            item.raw_issue["validator_v2_stop_reason"] = stop_reason
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                stop_reason=stop_reason,
                reasoning={
                    "fact_timeout": "所需的确定性事实提供方执行超时。",
                    "unsupported_fact": "所需的确定性事实提供方不可用。",
                    "duplicate_fact_request": "所需的事实集合此前已尝试过。",
                }.get(stop_reason, "事实消解未产生新的决策证据。"),
            )

        previous_hashes = item.raw_issue.setdefault("validator_evidence_delta_hashes", [])
        if not isinstance(previous_hashes, list):
            previous_hashes = []
            item.raw_issue["validator_evidence_delta_hashes"] = previous_hashes
        if batch.evidence_delta_hash in previous_hashes:
            item.raw_issue["validator_v2_stop_reason"] = "duplicate_fact_request"
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                stop_reason="duplicate_fact_request",
                reasoning="已消解的事实集合此前已完成评估。",
            )
        previous_hashes.append(batch.evidence_delta_hash)

        response = validator_agent.run(
            self._validator_input(
                item.raw_issue,
                item.issue_code,
                item.evidence_pack,
                validation_pass="evidence_recheck",
                evidence_delta=batch.evidence_delta,
            )
        )
        self._merge_response_metadata(token_metadata, getattr(response, "metadata", {}) or {})
        if not response.success or not isinstance(response.data, dict):
            item.raw_issue["validator_v2_stop_reason"] = "no_evidence_gain"
            if response.error:
                item.raw_issue["validator_v2_error"] = str(response.error)[:500]
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                validation_pass="evidence_recheck",
                stop_reason="no_evidence_gain",
                reasoning="V2 证据复检未能产出有效决策。",
            )
        revised = dict(response.data)
        if str(revised.get("schema_version") or "") != "zscope.validator-result.v3":
            item.raw_issue["validator_v2_stop_reason"] = "malformed_output"
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                validation_pass="evidence_recheck",
                stop_reason="malformed_output",
                reasoning="V2 证据复检返回了非 v3 格式的结果。",
            )
        item.raw_issue.setdefault("validator_pass_history", []).append(
            {
                "pass": "evidence_recheck",
                "verdict": validation_verdict(revised),
                "stop_reason": str(revised.get("stop_reason") or ""),
                "evidence_delta_hash": batch.evidence_delta_hash,
                "fact_kinds": list(batch.evidence_delta.get("fact_kinds") or []),
            }
        )
        token_metadata["validator_evidence_recheck_count"] = (
            int(token_metadata.get("validator_evidence_recheck_count", 0) or 0) + 1
        )
        return revised

    def _terminal_from_prior_for_v3(
        self,
        item: _PreparedValidation,
        prior: Dict[str, Any],
        *,
        stop_reason: str,
        reasoning: str,
        validation_pass: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retain a terminal V1 verdict while making unresolved work explicit."""

        verdict = validation_verdict(prior)
        if verdict in {"verified", "rejected"}:
            revised = dict(prior)
            revised["stop_reason"] = stop_reason
            revised["reasoning"] = reasoning[:4000]
            revised["missing_fact_request"] = None
            if validation_pass is not None:
                revised["pass"] = validation_pass
            return revised
        return self._terminal_uncertain_v3_result(
            item,
            prior,
            validation_pass=validation_pass or str(prior.get("pass") or "initial"),
            stop_reason=stop_reason,
            reasoning=reasoning,
        )

    def _run_v3_targeted_investigation(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        if (
            not item.allow_v3
            or str(val_data.get("schema_version") or "") != "zscope.validator-result.v3"
            or not self._model_result_requires_review(item, val_data)
        ):
            return val_data
        investigate = getattr(validator_agent, "investigate", None)
        if not callable(investigate):
            return val_data
        item.raw_issue["validator_v3_entered"] = True
        # Rebuild the pass projection so V3 sees any V2 fact delta/proofs but
        # not the model's hidden reasoning history.
        investigation_input = self._validator_input(
            item.raw_issue,
            item.issue_code,
            item.evidence_pack,
            validation_pass="investigation_synthesis",
            evidence_delta={
                "prior_passes": list(item.raw_issue.get("validator_pass_history") or []),
                "fact_resolution": item.raw_issue.get("validator_fact_resolution") or {},
            },
        )
        if self._review_enabled():
            positive = (
                self._review_flag("validation_positive_case")
                and validation_verdict(val_data) == "uncertain"
            )
            item.raw_issue["review_v3_entry_pool"] = validation_verdict(val_data)
            item.raw_issue["review_v3_objective"] = (
                "positive_case" if positive else "neutral_investigation"
            )
            investigation_input["review_positive_case"] = positive
            investigation_input["review_rejection_expected"] = (
                validation_verdict(val_data) == "rejected"
            )
            item.raw_issue.setdefault("review_prior_results", []).append(deepcopy(val_data))
            self._review_checkpoint(item.raw_issue, "before_v3")
        response = investigate(
            investigation_input,
            max_iterations=item.v3_max_iterations or 50,
        )
        self._merge_response_metadata(
            token_metadata,
            getattr(response, "metadata", {}) or {},
        )
        if not response.success or not isinstance(response.data, dict):
            item.raw_issue["validator_v3_stop_reason"] = "investigation_exhausted"
            if response.error:
                item.raw_issue["validator_v3_error"] = str(response.error)[:500]
            return self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="investigation_exhausted",
                reasoning="V3 定向排查未能产出有效决策。",
            )
        revised = dict(response.data)
        self._apply_review_metadata(item.raw_issue, getattr(response, "metadata", {}) or {})
        if str(revised.get("schema_version") or "") != "zscope.validator-result.v3":
            item.raw_issue["validator_v3_stop_reason"] = "malformed_output"
            return self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="malformed_output",
                reasoning="V3 定向排查返回了非 v3 格式的结果。",
            )
        self._apply_v3_investigation_facts(
            item.raw_issue,
            revised,
            getattr(response, "metadata", {}) or {},
        )
        item.raw_issue.setdefault("validator_pass_history", []).append(
            {
                "pass": "investigation_synthesis",
                "verdict": validation_verdict(revised),
                "stop_reason": str(revised.get("stop_reason") or ""),
                "max_iterations": item.v3_max_iterations or 50,
                "model_iterations": int(
                    (getattr(response, "metadata", {}) or {}).get("iterations", 0) or 0
                ),
                "tool_call_count": int(
                    (getattr(response, "metadata", {}) or {}).get("tool_call_count", 0) or 0
                ),
                "new_fact_count": len(item.raw_issue.get("v3_investigation_facts") or []),
            }
        )
        token_metadata["validator_targeted_investigation_count"] = (
            int(token_metadata.get("validator_targeted_investigation_count", 0) or 0) + 1
        )
        return revised

    _V2B_MAX_ITERATIONS = 12

    def _v2b_adjudication_enabled(self) -> bool:
        """Plan M5 R3: V2b runs only when explicitly enabled (default off)."""
        analysis_cfg = getattr(self.config, "analysis", None)
        return (
            analysis_cfg is not None
            and getattr(analysis_cfg, "validation_v2b_adjudication", False) is True
        )

    def _run_v2b_adjudication(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Adjudicate a rejection that would otherwise park as rejected-unproven.

        The V2b pass audits the prior rejection adversarially: an overturn
        (verdict=verified) re-enters the confirmation path with tool-backed
        facts; an upheld rejection either gains blocking evidence (terminal
        rejected) or stays needs_review with the adjudication recorded.  The
        deciding-rung attribution keys off the ``v2b_adjudication`` pass
        history entry / ``validator_v2b_entered`` flag.
        """
        if not self._v2b_adjudication_enabled():
            return val_data
        if str(val_data.get("schema_version") or "") != "zscope.validator-result.v3":
            return val_data
        if validation_verdict(val_data) != "rejected":
            return val_data
        if not self._model_result_requires_review(item, val_data):
            # The rejection already terminalizes (deterministic proof) — the
            # proof-polarity path owns it; no adjudication needed.
            return val_data
        investigate = getattr(validator_agent, "investigate", None)
        if not callable(investigate):
            return val_data
        item.raw_issue["validator_v2b_entered"] = True
        adjudication_input = self._validator_input(
            item.raw_issue,
            item.issue_code,
            item.evidence_pack,
            validation_pass="v2b_adjudication",
            evidence_delta={
                "prior_passes": list(item.raw_issue.get("validator_pass_history") or []),
                "fact_resolution": item.raw_issue.get("validator_fact_resolution") or {},
                "adjudication_context": {
                    "rejected_verdict_reasoning": str(val_data.get("reasoning") or "")[:2000],
                    "prior_stop_reason": str(val_data.get("stop_reason") or ""),
                    "adjudication_objective": "audit-the-rejection",
                },
            },
        )
        if self._review_enabled():
            adjudication_input["review_rejection_expected"] = True
            item.raw_issue.setdefault("review_prior_results", []).append(deepcopy(val_data))
            self._review_checkpoint(item.raw_issue, "before_v2b")
        response = investigate(
            adjudication_input,
            max_iterations=self._V2B_MAX_ITERATIONS,
            pass_kind="v2b_adjudication",
        )
        self._merge_response_metadata(
            token_metadata,
            getattr(response, "metadata", {}) or {},
        )
        if not response.success or not isinstance(response.data, dict):
            item.raw_issue["validator_v2b_stop_reason"] = "adjudication_exhausted"
            if response.error:
                item.raw_issue["validator_v2b_error"] = str(response.error)[:500]
            return val_data
        revised = dict(response.data)
        self._apply_review_metadata(item.raw_issue, getattr(response, "metadata", {}) or {})
        if (
            str(revised.get("schema_version") or "") != "zscope.validator-result.v3"
            or str(revised.get("pass") or "") != "v2b_adjudication"
        ):
            item.raw_issue["validator_v2b_stop_reason"] = "malformed_output"
            return val_data
        verdict = validation_verdict(revised)
        item.raw_issue["validator_v2b_action"] = {
            "rejected": "uphold",
            "verified": "overturn",
            "uncertain": "unresolved",
        }.get(verdict, "unresolved")
        self._apply_v3_investigation_facts(
            item.raw_issue,
            revised,
            getattr(response, "metadata", {}) or {},
        )
        item.raw_issue.setdefault("validator_pass_history", []).append(
            {
                "pass": "v2b_adjudication",
                "verdict": verdict,
                "action": item.raw_issue["validator_v2b_action"],
                "stop_reason": str(revised.get("stop_reason") or ""),
                "max_iterations": self._V2B_MAX_ITERATIONS,
                "model_iterations": int(
                    (getattr(response, "metadata", {}) or {}).get("iterations", 0) or 0
                ),
                "tool_call_count": int(
                    (getattr(response, "metadata", {}) or {}).get("tool_call_count", 0) or 0
                ),
                "new_fact_count": len(item.raw_issue.get("v3_investigation_facts") or []),
            }
        )
        token_metadata["validator_v2b_adjudication_count"] = (
            int(token_metadata.get("validator_v2b_adjudication_count", 0) or 0) + 1
        )
        return revised

    def _model_result_requires_review(
        self,
        item: _PreparedValidation,
        val_data: Dict[str, Any],
    ) -> bool:
        """Ask the real policy whether this model result already has authority."""

        probe = deepcopy(item.raw_issue)
        score_data = self.validation_pipeline.score_components(probe, val_data)
        outcome = self.validation_pipeline.apply_validator_result(
            probe,
            val_data,
            verdict=validation_verdict(val_data),
            score_data=score_data,
        )
        return outcome.memory_status in {"needs_review", "engine_failed"}

    @staticmethod
    def _apply_v3_investigation_facts(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> None:
        """Bind cited, tool-backed V3 claims into the promotion evidence slice."""

        raw_facts = metadata.get("validator_investigation_facts")
        facts = [dict(value) for value in raw_facts or [] if isinstance(value, dict)]
        raw_tool_catalog = metadata.get("validator_tool_fact_catalog")
        tool_catalog = (
            {
                str(uid): dict(record)
                for uid, record in raw_tool_catalog.items()
                if str(uid) and isinstance(record, dict)
            }
            if isinstance(raw_tool_catalog, dict)
            else {}
        )
        cited = {
            str(value)
            for value in val_data.get("evidence_refs") or []
            if isinstance(value, str) and value
        }
        accepted = []
        for fact in facts:
            fact_uid = str(fact.get("fact_uid") or "")
            backing_refs = fact.get("evidence_refs")
            backing_refs = (
                [str(value) for value in backing_refs if str(value)]
                if isinstance(backing_refs, list)
                else []
            )
            locations = fact.get("locations")
            has_locations = bool(
                isinstance(locations, list)
                and locations
                and all(isinstance(value, dict) for value in locations)
                and any(
                    any(field not in (None, "") for field in value.values())
                    for value in locations
                    if isinstance(value, dict)
                )
            )
            if (
                fact_uid in cited
                and str(fact.get("producer_engine") or "") == "validator_readonly_tool_session"
                and str(fact.get("dependency_code_hash") or "")
                and backing_refs
                and all(ref in tool_catalog for ref in backing_refs)
                and has_locations
            ):
                accepted.append(fact)
        issue["v3_investigation_fact_count"] = len(facts)
        issue["v3_investigation_cited_fact_count"] = len(accepted)
        issue["v3_tool_fact_catalog"] = tool_catalog
        if not accepted:
            issue["v3_evidence_closure"] = {
                "complete": False,
                "reason": "no_cited_tool_backed_fact",
                "resolved_fact_kinds": [],
            }
            return

        existing = issue.setdefault("v3_investigation_facts", [])
        if not isinstance(existing, list):
            existing = []
            issue["v3_investigation_facts"] = existing
        known = {str(value.get("fact_uid") or "") for value in existing if isinstance(value, dict)}
        for fact in accepted:
            uid = str(fact.get("fact_uid") or "")
            if uid and uid not in known:
                existing.append(fact)
                known.add(uid)

        fact_slice = issue.get("decision_fact_slice")
        fact_slice = dict(fact_slice) if isinstance(fact_slice, dict) else {}
        raw_missing = issue.get("missing_fact_kinds") or fact_slice.get("missing_fact_kinds") or []
        missing = set(normalize_missing_fact_kinds(raw_missing))
        resolved = {str(fact.get("fact_kind") or "") for fact in accepted if fact.get("fact_kind")}
        remaining = sorted(missing - resolved)
        fact_uids = {str(value) for value in fact_slice.get("fact_uids") or [] if str(value)}
        fact_payloads = [
            dict(value) for value in fact_slice.get("facts") or [] if isinstance(value, dict)
        ]
        known_payloads = {
            str(value.get("fact_uid") or value.get("uid") or value.get("id") or "")
            for value in fact_payloads
        }
        for fact in accepted:
            uid = str(fact.get("fact_uid") or "")
            if uid and uid not in known_payloads:
                fact_payloads.append(dict(fact))
                known_payloads.add(uid)
        fact_uids.update(str(fact.get("fact_uid")) for fact in accepted if fact.get("fact_uid"))
        code_hashes = {
            str(value) for value in fact_slice.get("dependency_code_hashes") or [] if str(value)
        }
        code_hashes.update(
            str(fact.get("dependency_code_hash"))
            for fact in accepted
            if fact.get("dependency_code_hash")
        )
        fact_slice.update(
            {
                "fact_uids": sorted(fact_uids),
                "dependency_code_hashes": sorted(code_hashes),
                "missing_fact_kinds": remaining,
                "coverage": "complete" if not remaining else "partial",
                "facts": fact_payloads,
            }
        )
        issue["decision_fact_slice"] = fact_slice
        issue["missing_fact_kinds"] = remaining
        issue["decision_fact_coverage"] = fact_slice["coverage"]
        complete = bool(not remaining and code_hashes and accepted)
        issue["v3_evidence_closure"] = {
            "complete": complete,
            "reason": "required_facts_closed" if complete else "required_facts_still_missing",
            "resolved_fact_kinds": sorted(resolved),
            "remaining_fact_kinds": remaining,
            "fact_uids": sorted(
                str(fact.get("fact_uid")) for fact in accepted if fact.get("fact_uid")
            ),
        }
        if complete:
            issue["candidate_promotion_eligible"] = True
            issue["candidate_promotion_reason"] = "v3_tool_evidence_complete"

    def _validator_evidence_slice_enabled(self) -> bool:
        return True

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
        retry_resp = validator_agent.run(
            self._validator_input(raw_issue, item.issue_code, retry_pack)
        )
        self._merge_response_metadata(token_metadata, getattr(retry_resp, "metadata", {}) or {})
        if not retry_resp.success:
            logger.warning(
                "Entry-root validation retry failed for issue %s: %s",
                raw_issue.get("id"),
                retry_resp.error,
            )
            return val_data

        retry_data = retry_resp.data
        return _as_dict(retry_data)

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

        target["context_tokens"] = int(target.get("context_tokens", 0) or 0) + token_value(
            "context_tokens"
        )
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
            "validator_repair_attempted",
            "validator_repair_accepted",
            "validator_final_tool_call_count",
            "validator_session_count",
            "validator_api_call_count",
            "multi_turn_outlier_count",
            "evidence_slice_token_count",
            "validator_turn_count",
            "validator_length_retry_count",
            "validator_protocol_exhausted",
            "validator_fact_resolution_count",
            "validator_fact_resolution_proof_count",
            "validator_evidence_recheck_count",
            "validator_investigation_trajectory_count",
            "validator_targeted_investigation_count",
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
        state["total_context_tokens"] = (
            int(state.get("total_context_tokens", 0) or 0) + context_tokens
        )
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
            ("validator_repair_attempted", "validator_repair_attempted"),
            ("validator_repair_accepted", "validator_repair_accepted"),
            ("validator_final_tool_call_count", "validator_final_tool_call_count"),
            ("validator_cache_hit", "validator_cache_hit"),
            ("validator_inflight_coalesced", "validator_inflight_coalesced"),
            ("validator_session_count", "validator_session_count"),
            ("validator_api_call_count", "validator_api_call_count"),
            ("multi_turn_outlier_count", "multi_turn_outlier_count"),
            ("evidence_slice_token_count", "evidence_slice_token_count"),
            ("validator_length_retry_count", "validator_length_retry_count"),
            ("validator_protocol_exhausted", "validator_protocol_exhausted_count"),
            ("validator_fact_resolution_count", "validator_fact_resolution_count"),
            (
                "validator_fact_resolution_proof_count",
                "validator_fact_resolution_proof_count",
            ),
            ("validator_evidence_recheck_count", "validator_evidence_recheck_count"),
            (
                "validator_investigation_trajectory_count",
                "validator_investigation_trajectory_count",
            ),
            (
                "validator_targeted_investigation_count",
                "validator_targeted_investigation_count",
            ),
            (
                "validation_soft_budget_overrun",
                "validation_soft_budget_overrun_count",
            ),
        ):
            try:
                value = int(metadata.get(source_key, 0) or 0)
            except (TypeError, ValueError):
                value = 0
            if value:
                state[state_key] = int(state.get(state_key, 0) or 0) + value

        turn_count = token_value("validator_turn_count")
        if turn_count:
            distribution = state.setdefault("validator_turn_distribution", {})
            key = str(turn_count)
            distribution[key] = int(distribution.get(key, 0) or 0) + 1
        session_count = token_value("validator_session_count")
        if session_count:
            stage = (
                "evidence_slice_v3"
                if token_value("evidence_slice_token_count")
                else "legacy_validator"
            )
            by_stage = state.setdefault("validator_prompt_tokens_by_stage", {})
            by_stage[stage] = int(by_stage.get(stage, 0) or 0) + cumulative_prompt

        try:
            overrun_seconds = float(
                metadata.get("validation_soft_budget_overrun_seconds", 0.0) or 0.0
            )
        except (TypeError, ValueError):
            overrun_seconds = 0.0
        if overrun_seconds > 0:
            state["validation_soft_budget_overrun_seconds"] = round(
                float(state.get("validation_soft_budget_overrun_seconds", 0.0) or 0.0)
                + overrun_seconds,
                4,
            )

    @staticmethod
    def _record_prevalidation_decision(
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        decision: Any,
    ) -> None:
        state["prevalidation_decision_count"] = (
            int(state.get("prevalidation_decision_count", 0) or 0) + 1
        )
        if decision.action == "audit_observation":
            state["static_audit_observation_count"] = (
                int(state.get("static_audit_observation_count", 0) or 0) + 1
            )
        if decision.action == "suppress":
            state["static_suppressed_count"] = int(state.get("static_suppressed_count", 0) or 0) + 1
        if raw_issue.get("candidate_source") == "clang_ast_cfg":
            state["clang_prevalidation_decision_count"] = (
                int(state.get("clang_prevalidation_decision_count", 0) or 0) + 1
            )

    @staticmethod
    def _record_deterministic_prevalidation_outcome(
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        outcome: ValidationOutcome,
    ) -> None:
        state["prevalidation_decision_count"] = (
            int(state.get("prevalidation_decision_count", 0) or 0) + 1
        )
        state["deterministic_prevalidation_decision_count"] = (
            int(state.get("deterministic_prevalidation_decision_count", 0) or 0) + 1
        )
        state["validator_avoided_count"] = int(state.get("validator_avoided_count", 0) or 0) + 1
        attribution = raw_issue.get("attribution")
        if not isinstance(attribution, dict):
            attribution = {
                "schema_version": "zscope.finding-attribution.v1",
                "discovered_by": [],
                "discovery_details": [],
            }
            raw_issue["attribution"] = attribution
        attribution["decided_by"] = "deterministic_proof"
        attribution["decision_level"] = "V0"
        raw_issue["model_verdict"] = None
        raw_issue["policy_disposition"] = str(
            raw_issue.get("candidate_disposition") or outcome.memory_status or "needs_review"
        )
        if raw_issue["policy_disposition"] in {"confirmed", "validated"}:
            raw_issue["confirmed_via"] = "deterministic_proof"
            attribution["confirmed_via"] = "deterministic_proof"
        if raw_issue.get("validator_v3_entered") is True:
            raw_issue["validator_v3_confirmed"] = raw_issue["policy_disposition"] in {
                "confirmed",
                "validated",
            }
        decision = str(raw_issue.get("deterministic_prevalidation_decision") or "")
        if decision == "confirmed":
            state["deterministic_prevalidation_confirmed_count"] = (
                int(state.get("deterministic_prevalidation_confirmed_count", 0) or 0) + 1
            )
        elif decision == "rejected_with_proof":
            state["deterministic_prevalidation_rejected_count"] = (
                int(state.get("deterministic_prevalidation_rejected_count", 0) or 0) + 1
            )
        elif outcome.report_bucket == "observations":
            state["deterministic_prevalidation_conflict_count"] = (
                int(state.get("deterministic_prevalidation_conflict_count", 0) or 0) + 1
            )
        if raw_issue.get("candidate_source") == "clang_ast_cfg":
            state["clang_prevalidation_decision_count"] = (
                int(state.get("clang_prevalidation_decision_count", 0) or 0) + 1
            )

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
        val_agent_cfg = next(
            (a for a in self.config.project.agents if a.name == "validator_agent"), None
        )
        profiles = getattr(getattr(self.config, "scan", None), "llm_profiles", None)
        # Public stage routing takes precedence. The Agent-local reference is
        # retained only for compatibility with pre-v2 effective configs.
        val_llm_ref = str(getattr(profiles, "validation", "") or "")
        if not val_llm_ref:
            val_llm_ref = str(
                val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
            )
        val_client = self.llm_clients.get(val_llm_ref, self.llm_clients["default"])
        validator_tools = (
            self.get_tools("validator_agent") if self._scan_depth() in {"balanced", "deep"} else []
        )
        return self.validator_agent_factory(
            val_client,
            validator_tools,
            tool_policy=self.tool_policy_for_agent("validator_agent"),
        )

    def _validator_enabled(self) -> bool:
        return any(a.name == "validator_agent" and a.enabled for a in self.config.project.agents)

    def _issue_function(self, raw_issue: Dict[str, Any], state: Dict[str, Any]) -> str:
        agent_context = _as_dict(state.get("agent_context"))
        default_func = str(agent_context.get("func_name") or state.get("entry_func") or "").strip()
        issue_func = str(raw_issue.get("function") or default_func).strip() or default_func
        if not issue_func or issue_func == default_func:
            return issue_func
        if self._get_function_impl(issue_func):
            return issue_func
        origin = self._indexed_external_api_origin(issue_func, default_func)
        if not origin:
            return issue_func

        for candidate in (
            raw_issue.get("entry_function"),
            raw_issue.get("analyzed_from"),
            state.get("entry_func"),
            default_func,
        ):
            fallback = str(candidate or "").strip()
            if not fallback or fallback == issue_func:
                continue
            if fallback == default_func or self._get_function_impl(fallback):
                self._record_issue_function_normalization(
                    raw_issue, issue_func, fallback, origin=origin
                )
                return fallback
        return issue_func

    def _issue_code(self, issue_func: str, state: Dict[str, Any]) -> str:
        issue_code = state["agent_context"]["code"]
        if issue_func != state["agent_context"]["func_name"]:
            impl = self._get_function_impl(issue_func)
            if impl:
                issue_code = impl["code"]
        return str(issue_code)

    def _get_function_impl(self, func_name: str) -> Optional[Dict[str, Any]]:
        getter = getattr(self.code_index, "get_function_impl", None)
        if not callable(getter):
            return None
        try:
            return cast(Optional[Dict[str, Any]], getter(func_name, warn_missing=False))
        except TypeError:
            return cast(Optional[Dict[str, Any]], getter(func_name))
        except Exception:
            return None

    def _indexed_external_api_origin(self, func_name: str, caller: str) -> str:
        classifier = getattr(self.code_index, "call_model_status", None)
        if not callable(classifier):
            return ""
        try:
            origin = classifier(func_name, caller=caller)
        except Exception:
            # Missing origin evidence must not move validation to another body.
            return ""
        if isinstance(origin, str) and origin in {"standard_model", "external_model_missing"}:
            return origin
        return ""

    @staticmethod
    def _record_issue_function_normalization(
        raw_issue: Dict[str, Any],
        original_func: str,
        normalized_func: str,
        *,
        origin: str,
    ) -> None:
        raw_issue.setdefault("sink_function", original_func)
        raw_issue["validation_function_normalized_from"] = original_func
        raw_issue["validation_function_normalization_reason"] = (
            "external_api_function_without_indexed_body"
        )
        raw_issue["validation_function_normalization_origin"] = origin
        raw_issue["function"] = normalized_func
        logger.info(
            "Normalized validation function for issue %s from external API %s to %s.",
            raw_issue.get("id"),
            original_func,
            normalized_func,
        )

    def _build_evidence_pack(
        self,
        raw_issue: Dict[str, Any],
        state: Dict[str, Any],
        issue_code: str,
    ) -> Dict[str, Any]:
        self._refresh_protocol_assessment(raw_issue)
        evidence_pack = build_validation_evidence_pack(
            raw_issue,
            state,
            issue_code,
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            score_components_fn=self.validation_pipeline.score_components,
            issue_key_fn=self.issue_key_fn,
        )
        if raw_issue.get("protocol_assessment"):
            evidence_pack["protocol_assessment"] = dict(raw_issue["protocol_assessment"])
        service = self.project_knowledge_service
        resolver = getattr(service, "resolve_for_candidate", None)
        if callable(resolver):
            try:
                knowledge = resolver(raw_issue, evidence_pack)
            except Exception as exc:
                logger.warning(
                    "Project knowledge resolution failed; preserving base evidence: %s", exc
                )
                knowledge = None
            if isinstance(knowledge, dict):
                try:
                    from ...wiki.service import validate_project_knowledge

                    validated_knowledge = validate_project_knowledge(knowledge)
                    if str(getattr(service, "mode", "active")) == "shadow":
                        # Shadow computes and records the exact selection but
                        # must not alter the Validator model input or verdict.
                        telemetry_fn = getattr(service, "telemetry_snapshot", None)
                        if callable(telemetry_fn):
                            state["wiki_telemetry"] = telemetry_fn()
                    else:
                        evidence_pack["project_knowledge"] = validated_knowledge
                except Exception as exc:
                    logger.warning(
                        "Project knowledge contract rejected; preserving base evidence: %s", exc
                    )
        return evidence_pack

    def _refresh_protocol_assessment(self, issue: Dict[str, Any]) -> None:
        from .protocol_assessment import (
            assess_protocol_candidate,
            is_protocol_candidate,
            reset_business_facts,
            publish_business_facts,
        )

        # A saved report, imported candidate or model cannot supply a current
        # replay receipt. Refresh even when the Validator model is disabled.
        issue.pop("protocol_assessment", None)
        if not is_protocol_candidate(issue):
            return
        for key in (
            "policy_disposition",
            "model_verdict",
            "validator_verdict",
            "validation_reasoning",
            "promotion_review_reason",
            "needs_review_sub_state",
        ):
            issue.pop(key, None)
        previous_proof = issue.get("decision_proof")
        if (
            isinstance(previous_proof, dict)
            and previous_proof.get("proof_kind")
            == "checked_object_protocol_with_business_declarations"
        ):
            for key in (
                "decision_proof",
                "proof_provider",
                "proof_coverage",
                "promotion_reason",
                "promotion_review_reason",
                "needs_review_sub_state",
            ):
                issue.pop(key, None)
        reset_business_facts(issue)
        try:
            registry = self.get_contract_registry() if self.get_contract_registry else None
            assessment = assess_protocol_candidate(
                issue, self.code_index, registry, self.validation_pipeline.review_memory.store
            )
            if assessment is not None:
                issue["protocol_assessment"] = assessment
                publish_business_facts(issue)
        except CancellationError:
            raise
        except Exception as exc:
            logger.warning("Object protocol replay unavailable; preserving pending: %s", exc)

    def _validator_input(
        self,
        raw_issue: Dict[str, Any],
        issue_code: str,
        evidence_pack: Dict[str, Any],
        *,
        validation_pass: str = "initial",
        evidence_delta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if self._validator_evidence_slice_enabled():
            finding_uid = str(
                raw_issue.get("candidate_uid")
                or raw_issue.get("candidate_id")
                or raw_issue.get("id")
                or "unknown-candidate"
            )
            validation_cluster_uid = str(
                raw_issue.get("validation_cluster_uid") or f"legacy:{finding_uid}"
            )
            evidence_slice = build_validator_evidence_slice_v3(
                raw_issue,
                evidence_pack,
                issue_code,
                validation_pass=validation_pass,
                evidence_delta=evidence_delta,
            )
            # build_validator_evidence_slice_v3 projects the optional Wiki
            # context and registers its refs without making it deterministic
            # proof.  Keep this fallback for custom evidence builders.
            if "project_knowledge" not in evidence_slice:
                knowledge = evidence_pack.get("project_knowledge")
                if isinstance(knowledge, dict):
                    evidence_slice["project_knowledge"] = knowledge
            obligation = _as_dict(evidence_slice.get("obligation"))
            if evidence_pack.get("protocol_assessment"):
                evidence_slice["protocol_assessment"] = evidence_pack["protocol_assessment"]
            obligation["candidate_uid"] = finding_uid
            obligation["validation_cluster_uid"] = validation_cluster_uid
            if self._review_facts_enabled():
                evidence_slice["review_facts"] = {
                    key: raw_issue.get(key)
                    for key in (
                        "review_fact_store",
                        "review_claim_checks",
                        "review_macro_branches",
                        "review_conditional_risks",
                    )
                }
                evidence_slice["review_fact_query"] = (
                    "query_validation_facts: ast_nodes/cfg/types/macros with symbol, offset, limit"
                )
            self._attach_review_memory_hint(evidence_slice, raw_issue)
            evidence_slice = self._fit_validator_slice(evidence_slice, max_tokens=12_000)
            raw_issue["validator_context_requires_retrieval"] = bool(
                evidence_slice.get("context_requires_retrieval")
            )
            serialized = json.dumps(
                evidence_slice,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            estimated_tokens = LLMClient.estimate_tokens([{"role": "user", "content": serialized}])
            raw_issue["validator_evidence_slice_version"] = VALIDATOR_EVIDENCE_SLICE_V3
            raw_issue["evidence_slice_token_count"] = int(estimated_tokens)
            val_input = {
                "validator_protocol": VALIDATOR_PROTOCOL_V3,
                "finding_uid": finding_uid,
                "validation_cluster_uid": validation_cluster_uid,
                "validation_pass": validation_pass,
                "evidence_slice": evidence_slice,
                "evidence_slice_token_count": int(estimated_tokens),
            }
            self.attach_agent_contract(val_input, "validator_agent")
            if self._review_enabled() and validation_pass in {
                "investigation_synthesis",
                "v2b_adjudication",
            }:
                from .review_session import ReviewSession

                val_input["review_protocol_enabled"] = self._review_flag(
                    "validation_review_protocol"
                ) or self._review_flag("validation_positive_case")
                val_input["_review_session"] = ReviewSession(
                    self._review_checker(),
                    raw_issue,
                    related=self._review_flag("validation_related_findings"),
                    facts_enabled=self._review_facts_enabled(),
                    checkpoint=lambda: self._review_checkpoint(raw_issue, validation_pass),
                )
            return val_input

        legacy_projection = self._fit_validator_slice(
            {
                "code": {"function_context": issue_code},
                "evidence_pack": compact_validation_evidence_pack(evidence_pack),
            },
            max_tokens=12_000,
        )
        raw_issue["validator_context_requires_retrieval"] = bool(
            legacy_projection.get("context_requires_retrieval")
        )
        val_input = {
            "finding": json.dumps(
                compact_validation_finding(raw_issue),
                indent=2,
                ensure_ascii=False,
            ),
            "context_code": legacy_projection["code"]["function_context"],
            "evidence_pack": legacy_projection["evidence_pack"],
            "context_projection": {
                key: value
                for key, value in legacy_projection.items()
                if key not in {"code", "evidence_pack"}
            },
        }
        self.attach_agent_contract(val_input, "validator_agent")
        return val_input

    def _attach_review_memory_hint(
        self, evidence_slice: Dict[str, Any], issue: Dict[str, Any]
    ) -> None:
        """Attach bounded historical review hints without changing verdict authority."""
        project = getattr(self.config, "project", None)
        settings = getattr(project, "review_memory", None)
        if project is None or settings is None or getattr(settings, "mode", "off") != "active":
            return
        try:
            from ...review_memory.matcher import match_patterns
            from ...review_memory.projector import project_hints
            from ...review_memory.store import ReviewMemoryStore

            project_key = str(getattr(project, "project_id", "") or project.project_root)
            store = ReviewMemoryStore(project.project_root, settings.state_dir)
            hints = match_patterns(
                issue,
                store.list_proposals(project_id=project_key),
                project_id=project_key,
                limit=max(0, int(getattr(settings, "max_patterns_per_finding", 3))),
            )
            if hints:
                evidence_slice["review_memory"] = project_hints(
                    hints, token_budget=int(getattr(settings, "max_context_tokens", 1200))
                )
        except Exception as exc:
            logger.debug("Review Memory hint lookup failed: %s", exc)

    def _review_flag(self, name: str) -> bool:
        return getattr(getattr(self.config, "analysis", None), name, False) is True

    def _depth_scoped_flag(self, name: str) -> bool:
        """Resolve a tri-state validation flag with scan-depth defaults.

        ``None`` means automatic: enabled for ``balanced`` scans (the depth
        where the FP-suppression guards were verified), disabled elsewhere.
        An explicit True/False in the runtime spec always wins.
        """
        raw = getattr(getattr(self.config, "analysis", None), name, None)
        if raw is None:
            depth = str(getattr(getattr(self.config, "scan", None), "depth", "") or "").lower()
            return depth == "balanced"
        return raw is True

    def _validate_related_candidates(
        self, state: Dict[str, Any], parents: List[Dict[str, Any]]
    ) -> None:
        from ...orchestration.candidates import CandidateLedger, CandidateRegistrar
        from .review_checkpoint import RelatedCandidateRegistry

        # An experiment must not acquire normal report visibility by emitting
        # a second-generation proposal through the review appendix.
        parents = [
            parent
            for parent in parents
            if not ValidationPipeline._is_conditional_snapshot_shadow(parent)
        ]
        children = RelatedCandidateRegistry(parents).freeze()
        if not self._review_flag("validation_related_findings"):
            children = [
                child
                for child in children
                if child.get("analysis_scope") == "conditional_source_branch"
            ]
        if not children:
            return
        main = state.get("candidate_ledger")
        ledger = CandidateLedger(
            project_id=str(getattr(main, "project_id", "project")),
            project_root=str(self.config.project.project_root),
            revision=str(getattr(main, "revision", "")),
        )
        CandidateRegistrar(ledger, run_id=str(state.get("run_id") or "")).register_issues(
            children,
            source="validator_related_discovery",
            default_entry_identity=str(
                state.get("entry_identity") or state.get("entry_func") or ""
            ),
            force_unconfirmed=True,
        )
        ledger.freeze()
        attach = getattr(main, "attach_review_appendix", None)
        if callable(attach):
            attach(ledger)
        # Terminal review defaults make interrupted children visible. A normal
        # validation overwrites them through the same lifecycle policy.
        for child in children:
            self._require_current_inputs()
            ledger.mark_issue_terminal(child, disposition="needs_review", status="needs_review")
        state.setdefault("review_related_candidates", []).extend(children)
        old_pending = state.get("pending_new_issues")
        state["pending_new_issues"] = children
        state["candidate_ledger"] = ledger
        state["_validating_review_appendix"] = True
        try:
            self.run(state)
        finally:
            for child in children:
                if child.get("candidate_disposition") == "needs_review" and child not in state.get(
                    "observations", []
                ):
                    state.setdefault("observations", []).append(child)
                self._update_candidate_ledger(state, child)
                self._review_checkpoint(child, "related_terminal_or_interrupted")
            state["candidate_ledger"] = main
            state["pending_new_issues"] = old_pending
            state.pop("_validating_review_appendix", None)

    def _review_enabled(self) -> bool:
        # Tri-state flags (None = depth-scoped) resolve through their own
        # helpers; plain flags keep the bool semantics here.
        if self._checked_proofs_enabled():
            return True
        return any(
            self._review_flag(name)
            for name in (
                "validation_review_protocol",
                "validation_positive_case",
                "validation_related_findings",
                "validation_review_checkpoint",
            )
        )

    def _review_facts_enabled(self) -> bool:
        return self._checked_proofs_enabled() or self._review_flag("validation_related_findings")

    def _checked_proofs_enabled(self) -> bool:
        """Depth-scoped checked-proofs switch with a toolchain safety gate.

        Even when depth-enabled, the feature stays off unless every
        compile_commands driver resolves to the fact compiler — checked
        claims about a cc build cannot be derived with Clang facts.
        """
        if not self._depth_scoped_flag("validation_checked_proofs"):
            return False
        project = getattr(self.config, "project", None)
        if project is None or not getattr(project, "project_root", None):
            return False
        try:
            return bool(self._review_checker().store.driver_bound())
        except Exception:  # pragma: no cover - fail closed on any gate error
            return False

    def _review_checker(self) -> Any:
        with self._review_init_lock:
            if self._review_checker_instance is None:
                from ...retrieval.validation_facts import scan_compiler_facts
                from .review_checks import ReviewClaimChecker

                project = self.config.project
                root = Path(project.project_root).resolve()
                commands = Path(
                    getattr(project, "compile_commands_path", None)
                    or root / "compile_commands.json"
                )
                directory = (
                    Path(getattr(self.config.analysis, "snapshot_dir", ".zscope_snapshots"))
                    / "review_experiment"
                )
                registry = self.get_contract_registry() if self.get_contract_registry else None
                self._review_checker_instance = ReviewClaimChecker(
                    scan_compiler_facts(self.code_index, root, commands, directory / "facts"),
                    registry,
                    getattr(self.code_index, "get_function_program_facts", None),
                )
            return self._review_checker_instance

    def _review_checkpoint(self, issue: Dict[str, Any], stage: str) -> None:
        self._require_current_inputs()
        if not self._review_enabled():
            return
        from .review_checkpoint import ReviewCheckpointStore

        checker = self._review_checker()
        uid = str((issue.get("review_fact_store") or {}).get("fact_store_id") or "")
        facts = checker.store.load(uid)
        runtime = {
            name: self._review_flag(name)
            for name in (
                "validation_review_protocol",
                "validation_checked_proofs",
                "validation_positive_case",
                "validation_related_findings",
                "validation_v2b_adjudication",
                "validation_v3_reattempt",
                "validation_review_checkpoint",
            )
        }
        ReviewCheckpointStore(checker.store.directory.parent / "checkpoints").save(
            issue, stage=stage, facts=facts, runtime=runtime
        )

    def _apply_review_metadata(self, issue: Dict[str, Any], metadata: Dict[str, Any]) -> None:
        if not self._review_enabled():
            return
        for key in ("review_adjudication", "review_disposition_reason"):
            if key in metadata:
                issue[key] = deepcopy(metadata[key])
        if metadata.get("review_tool_results") and not issue.get("review_tool_results"):
            issue.setdefault("review_tool_results", []).extend(
                deepcopy(metadata["review_tool_results"])
            )
        if issue.get("review_disposition_reason") == "rejection_refuted_unconfirmed":
            issue["review_priority_signal"] = "refuted_rejection_without_defect_confirmation"
        self._review_checkpoint(issue, "after_investigation")

    @staticmethod
    def _fit_validator_slice(
        evidence_slice: Dict[str, Any],
        *,
        max_tokens: int,
    ) -> Dict[str, Any]:
        from .context_budget import fit_evidence

        return fit_evidence(evidence_slice, max_tokens=max_tokens)

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
