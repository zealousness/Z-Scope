"""Validation runner that orchestrates Validator calls and dispositions."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import time
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import Event, Lock
from typing import Any, Callable, Dict, List, Mapping, Optional, cast

from ...agents.validator_agent.agent import ValidatorAgent
from ...common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from ...common.issue_identity import canonical_issue_key, deduplicate_issues
from ...config.function_entry import FunctionEntry
from ...framework.llm_client import LLMClient
from ...orchestration.scheduler import VALIDATOR_ROLE, ScanScheduler
from ...orchestration.decision_trace import ensure_decision_trace_store
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
from .fact_capabilities import (
    EvidenceAction,
    FactCapabilityRegistry,
    FunctionIRFactService,
    verify_certificate_v2,
)
from .claim_verifier import (
    EvidenceClaimRequest,
    EvidenceClaimVerifier,
    verify_evidence_certificate,
)
from .authority import TerminalAuthorityEvaluator

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
    _VALIDATION_CACHE_PROTOCOL = "zscope.validator-cache.v8"
    _DEFAULT_VALIDATION_CACHE_SIZE = 4096
    _TRANSIENT_VALIDATOR_STOP_REASONS = frozenset(
        {
            "fact_timeout",
            "malformed_output",
            "output_truncated",
        }
    )
    _EXTERNAL_API_NAMES = {
        "calloc",
        "close",
        "free",
        "malloc",
        "memcpy",
        "memmove",
        "memset",
        "open",
        "pthread_create",
        "read",
        "realloc",
        "recv",
        "send",
        "snprintf",
        "sprintf",
        "strcpy",
        "strncpy",
        "thrd_create",
        "write",
    }

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
        self.scheduler = scheduler
        # Validator verdicts are contextual.  Keeping this cache on the runner
        # scopes it to one immutable scan instead of leaking decisions between
        # projects, revisions, entries, or long-lived service requests.
        self._validator_result_cache_size = self._validation_cache_size()
        self._validator_result_cache = result_cache or ValidationResultCache(
            self._validator_result_cache_size
        )
        self._validation_environment_fingerprint = self._build_validation_environment_fingerprint()
        compile_commands_path = getattr(code_index, "compile_commands_path", None)
        ir_enabled = self._scan_depth() in {"balanced", "deep"}
        self._function_ir_facts = FunctionIRFactService(
            Path(compile_commands_path) if compile_commands_path else None,
            enabled=ir_enabled,
        )
        self._fact_capabilities = FactCapabilityRegistry(self._function_ir_facts)
        self._evidence_completion_queue = EvidenceCompletionQueue(
            enabled=True,
            max_workers=config.concurrency.evidence_completion_workers,
            enable_v11_providers=False,
            enable_v12_providers=False,
            certified_fact_provider=self._function_ir_facts.resolve_first,
            require_replayable_certificates=True,
        )
        self._decision_trace_store = ensure_decision_trace_store(config)
        project_root = Path(getattr(getattr(config, "project", None), "project_root", ".") or ".")
        validation_profile = str(
            getattr(getattr(getattr(config, "scan", None), "llm_profiles", None), "validation", "")
            or "default"
        )
        validation_client = llm_clients.get(validation_profile) or llm_clients.get("default")
        model_identity = self._llm_identity(validation_client) if validation_client else {}
        provider_urls = tuple(
            str(value) for value in getattr(validation_client, "base_urls", []) or []
        )
        self._decision_trace_store.update_identity(
            {
                "project_revision": self._project_revision(project_root),
                "validation_environment_sha256": self._validation_environment_fingerprint,
                "effective_rules_sha256": self._effective_rules_sha256(),
                "validator_protocol": VALIDATOR_PROTOCOL_V3,
                "model_identity_sha256": self._stable_hash(model_identity),
                "provider_identity_sha256": self._stable_hash(provider_urls),
                "prompt_contract_sha256": self._validation_environment_fingerprint,
            }
        )
        self._evidence_claim_verifier = EvidenceClaimVerifier(
            allow_legacy_observation_claims=False
        )
        self._terminal_authority = TerminalAuthorityEvaluator()

    @staticmethod
    def _trace_cluster_uid(issue: Dict[str, Any]) -> str:
        pack = _as_dict(issue.get("evidence_pack"))
        return str(issue.get("validation_cluster_uid") or pack.get("validation_cluster_uid") or "")

    def _trace_event(
        self,
        issue: Dict[str, Any],
        *,
        stage: str,
        actor: str,
        reason_code: str,
        before_state: Optional[Dict[str, Any]] = None,
        after_state: Optional[Dict[str, Any]] = None,
        input_refs: tuple[str, ...] = (),
        output_refs: tuple[str, ...] = (),
        call_ids: tuple[str, ...] = (),
        tool_call_ids: tuple[str, ...] = (),
        token_delta: int = 0,
        details: Optional[Dict[str, Any]] = None,
        dedupe_key: str = "",
    ) -> None:
        cluster_uid = self._trace_cluster_uid(issue)
        if not cluster_uid:
            return
        try:
            self._decision_trace_store.append_event(
                cluster_uid,
                stage=stage,
                actor=actor,
                reason_code=reason_code,
                before_state=before_state,
                after_state=after_state or self._trace_state(issue),
                input_refs=input_refs,
                output_refs=output_refs,
                disposition_before=str((before_state or {}).get("candidate_disposition") or ""),
                disposition_after=str(issue.get("candidate_disposition") or ""),
                call_ids=call_ids,
                tool_call_ids=tool_call_ids,
                token_delta=token_delta,
                closed_clause_ids=tuple(self._closed_clause_ids(issue)),
                open_clause_ids=tuple(self._open_clause_ids(issue)),
                details=details,
                dedupe_key=dedupe_key,
            )
        except Exception as exc:
            logger.warning("Decision trace append failed for %s: %s", cluster_uid, exc)

    @staticmethod
    def _trace_state(issue: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: deepcopy(issue.get(key))
            for key in (
                "candidate_uid",
                "validation_cluster_uid",
                "candidate_disposition",
                "validation_status",
                "model_verdict",
                "policy_disposition",
                "deterministic_prevalidation_decision",
                "proof_coverage",
                "evidence_conflict",
                "decision_fact_coverage",
                "missing_fact_kinds",
                "evidence_closure_state",
                "v3_evidence_closure",
            )
            if issue.get(key) not in (None, "", [], {})
        }

    @staticmethod
    def _open_clause_ids(issue: Dict[str, Any]) -> List[str]:
        closure = issue.get("evidence_closure_state")
        closure = closure if isinstance(closure, dict) else {}
        values = closure.get("missing_fact_kinds") or issue.get("missing_fact_kinds") or []
        return (
            sorted({str(value) for value in values if str(value)})
            if isinstance(values, list)
            else []
        )

    @staticmethod
    def _closed_clause_ids(issue: Dict[str, Any]) -> List[str]:
        closure = issue.get("evidence_closure_state")
        closure = closure if isinstance(closure, dict) else {}
        values = closure.get("resolved_fact_kinds") or []
        return (
            sorted({str(value) for value in values if str(value)})
            if isinstance(values, list)
            else []
        )

    def _cluster_usage_events(self, issue: Dict[str, Any]) -> List[Dict[str, Any]]:
        ledger = getattr(self.config, "scan_token_usage_ledger", None)
        getter = getattr(ledger, "events_for_cluster", None)
        if not callable(getter):
            return []
        return list(getter(self._trace_cluster_uid(issue)))

    def _record_model_trace(
        self,
        issue: Dict[str, Any],
        *,
        stage: str,
        structured_input: Dict[str, Any],
        structured_output: Dict[str, Any],
        usage_start: int,
        reason_code: str,
        tool_call_ids: tuple[str, ...] = (),
        evidence_refs: tuple[str, ...] = (),
    ) -> None:
        events = self._cluster_usage_events(issue)[usage_start:]
        call_ids = tuple(
            str(value.get("call_id") or "") for value in events if value.get("call_id")
        )
        token_delta = sum(int(value.get("total_tokens") or 0) for value in events)
        ref = self._decision_trace_store.put_model_event(
            call_identity=f"{self._trace_cluster_uid(issue)}:{stage}:{usage_start}",
            stage=stage,
            validation_cluster_uid=self._trace_cluster_uid(issue),
            structured_input=structured_input,
            structured_output=structured_output,
            call_ids=call_ids,
            tool_call_ids=tool_call_ids,
            prompt_revision=VALIDATOR_PROTOCOL_V3,
            prompt_hash=self._validation_environment_fingerprint,
        )
        self._trace_event(
            issue,
            stage=stage,
            actor="validator_agent",
            reason_code=reason_code,
            output_refs=(ref, *evidence_refs),
            call_ids=call_ids,
            tool_call_ids=tool_call_ids,
            token_delta=token_delta,
            details={
                "verdict": validation_verdict(structured_output),
                "pass": structured_output.get("pass"),
                "stop_reason": structured_output.get("stop_reason"),
            },
            dedupe_key=f"model:{stage}:{':'.join(call_ids) or usage_start}",
        )

    def run(self, state: Dict[str, Any]) -> None:
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
                            self._validate_with_deadline,
                            item,
                            parent_token=parent_token,
                            priority=int(item.raw_issue.get("priority_score") or 0),
                        )
                    else:
                        assert executor is not None
                        future = executor.submit(
                            self._validate_with_deadline,
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

        state["pending_new_issues"] = []
        state["validation_queue_drained"] = True

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
        raw = getattr(analysis_cfg, "validation_deadline_seconds", 240.0)
        if raw is None:
            return None
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return 240.0
        return value if value > 0 else None

    def _deterministic_prevalidation_enabled(self) -> bool:
        return True

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
        eligible = []
        for item in prepared:
            issue = item.raw_issue
            severity = str(issue.get("impact_level") or issue.get("severity") or "").lower()
            externally_reachable = self._externally_reachable(item)
            valid_obligation = self._has_valid_security_obligation(issue)
            closable_gap = self._has_readonly_closable_gap(issue, item.evidence_pack)
            shadow_only = self._is_shadow_only_candidate(issue)
            selected = False
            reason = "not_selected"
            if shadow_only:
                reason = "shadow_only"
            elif not valid_obligation:
                reason = "missing_security_obligation"
            elif not closable_gap:
                reason = "no_readonly_closable_gap"
            elif bool(issue.get("proof_conflict_requires_v3")):
                selected = True
                reason = "unresolved_valid_proof_conflict"
            elif depth == "deep":
                selected = True
                reason = "deep_all_unclosed_without_counterproof"
            elif not (self._v3_is_high_or_critical(item) or externally_reachable):
                reason = "balanced_risk_and_reachability_gate"
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
                "risk_basis": self._v3_risk_basis(item),
                "required_fact_kinds": list(
                    EvidenceCompletionQueue.required_resolution_fact_kinds(
                        issue,
                        {"verdict": "uncertain"},
                    )
                ),
            }
            if not selected:
                not_eligible_code = (
                    "V3_NOT_ELIGIBLE_NO_EXECUTABLE_GAP"
                    if reason in {"missing_security_obligation", "no_readonly_closable_gap"}
                    else "V3_NOT_ELIGIBLE_RISK"
                )
                self._trace_event(
                    issue,
                    stage="V3",
                    actor="v3_eligibility_policy",
                    reason_code=not_eligible_code,
                    details=deepcopy(issue["validator_v3_eligibility"]),
                    dedupe_key=f"v3-ineligible:{reason}:{self._trace_cluster_uid(issue)}",
                )
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

    @staticmethod
    def _v3_risk_basis(item: _PreparedValidation) -> Dict[str, Any]:
        """Explain eligibility using only candidate and project-graph facts."""

        issue = item.raw_issue
        entry = item.evidence_pack.get("entry_context")
        entry = entry if isinstance(entry, dict) else {}
        severity_field = "impact_level" if issue.get("impact_level") else "severity"
        explicit_field = "risk_score" if issue.get("risk_score") is not None else "priority_score"
        external_sources = [
            name
            for name, value in (
                ("candidate.externally_reachable", issue.get("externally_reachable")),
                ("candidate.reachable_from_entry", issue.get("reachable_from_entry")),
                ("entry.entry_is_external_root", entry.get("entry_is_external_root")),
                ("entry.reachable_from_entry", entry.get("reachable_from_entry")),
            )
            if bool(value)
        ]
        return {
            "severity": str(issue.get(severity_field) or "unknown").lower(),
            "severity_source": f"candidate.{severity_field}",
            "explicit_risk_score": issue.get(explicit_field) or 0,
            "explicit_risk_source": f"candidate.{explicit_field}",
            "computed_risk_score": ValidationRunner._v3_risk_score(item),
            "external_reachability_sources": external_sources,
            "truth_fields_consulted": False,
        }

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

    def _has_readonly_closable_gap(
        self,
        issue: Dict[str, Any],
        evidence_pack: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        fact_kinds = self._remaining_fact_kinds(issue)
        if not fact_kinds:
            issue["fact_capabilities"] = []
            issue["validator_evidence_actions"] = []
            return False
        capabilities = self._fact_capabilities.inspect(issue, evidence_pack, fact_kinds)
        actions = self._fact_capabilities.executable_actions(issue, evidence_pack, fact_kinds)
        issue["fact_capabilities"] = [value.to_dict() for value in capabilities]
        issue["validator_evidence_actions"] = [value.to_dict() for value in actions]
        return bool(actions)

    @staticmethod
    def _remaining_fact_kinds(issue: Mapping[str, Any]) -> tuple[str, ...]:
        closure = issue.get("evidence_closure_state")
        if isinstance(closure, Mapping):
            missing = closure.get("missing_fact_kinds")
            if isinstance(missing, list):
                return tuple(sorted({str(value) for value in missing if str(value)}))
        return EvidenceCompletionQueue.required_resolution_fact_kinds(
            issue,
            {"verdict": "uncertain"},
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
            score_data = self.validation_pipeline.score_components(raw_issue, {})
            outcome = self.validation_pipeline.apply_unvalidated(raw_issue, score_data)
            if outcome.report_bucket:
                state[outcome.report_bucket].append(raw_issue)
            self._update_candidate_ledger(state, raw_issue)

    def _run_fact_first_prevalidation(
        self,
        issue: Dict[str, Any],
        evidence_pack: Mapping[str, Any],
    ) -> tuple[Any, Optional[ValidationOutcome]]:
        """Resolve the immutable obligation before the first model call."""

        if not self._has_valid_security_obligation(issue):
            issue["fact_first_resolution"] = {
                "status": "not_applicable",
                "reason": "missing_security_obligation",
            }
            return None, None
        try:
            batch = self._evidence_completion_queue.resolve_required_facts(
                issue,
                validator_data={"verdict": "uncertain"},
                validation_evidence=evidence_pack,
            )
        except Exception as exc:
            issue["fact_first_resolution"] = {
                "status": "provider_error",
                "error": f"{type(exc).__name__}: {exc}"[:500],
            }
            return None, None
        issue["fact_first_resolution"] = {
            "status": str(issue.get("evidence_completion_status") or "not_applicable"),
            "evidence_delta_hash": batch.evidence_delta_hash,
            "proof_added": batch.proof_added,
            "fact_kinds": [value.fact_kind for value in batch.resolutions],
            "resolutions": [
                {
                    "fact_kind": value.fact_kind,
                    "status": value.terminal_status,
                    "provider_ids": list(value.provider_ids),
                    "miss_reason": value.miss_reason,
                }
                for value in batch.resolutions
            ],
        }
        issue["fact_first_attempted_fact_kinds"] = sorted(
            {value.fact_kind for value in batch.resolutions if value.fact_kind}
        )
        if batch.evidence_delta:
            issue["fact_first_evidence_delta"] = deepcopy(batch.evidence_delta)
        for resolution in batch.resolutions:
            code = {
                "resolved": "FACT_VERIFIED_TRUE",
                "conflicting": "FACT_CONFLICTING",
                "timeout": "PROVIDER_TIMEOUT",
                "provider_error": "PROVIDER_ERROR",
                "no_match": "PROVIDER_NO_MATCH",
            }.get(resolution.terminal_status, "FACT_UNKNOWN")
            self._trace_event(
                issue,
                stage="provider",
                actor="fact_first_evidence_completion",
                reason_code=code,
                details={
                    "fact_kind": resolution.fact_kind,
                    "status": resolution.terminal_status,
                    "provider_ids": list(resolution.provider_ids),
                    "miss_reason": resolution.miss_reason,
                },
                dedupe_key=(
                    f"fact-first:{resolution.fact_kind}:{resolution.terminal_status}:"
                    f"{batch.evidence_delta_hash or 'no-delta'}"
                ),
            )
        if not batch.proof_added:
            return batch, None
        outcome = self.validation_pipeline.apply_deterministic_prevalidation(
            issue,
            self.validation_pipeline.score_components(issue, {}),
        )
        return batch, outcome

    def _prepare_issue_for_validation(
        self,
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        index: int,
    ) -> Optional[_PreparedValidation]:
        self._ensure_discovery_attribution(raw_issue)
        issue_func = self._issue_function(raw_issue, state)
        logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)

        ledger = state.get("candidate_ledger")
        mark_running = getattr(ledger, "mark_validation_running", None)
        if callable(mark_running):
            mark_running(raw_issue)

        decision = self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
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
        evidence_ref = self._decision_trace_store.put_evidence(
            kind="validator_evidence_pack",
            payload=evidence_pack,
            producer="validation_runner",
            dependency_hashes=tuple(
                str(value)
                for value in _as_dict(raw_issue.get("decision_fact_slice")).get(
                    "dependency_code_hashes", []
                )
                if str(value)
            ),
        )
        if self._deterministic_prevalidation_enabled():
            # V0 consumes producer-owned deterministic proofs already attached
            # to the candidate. Legacy local completion heuristics are not
            # allowed to manufacture a complete proof in certificate mode;
            # FunctionIR fact-first runs below for unresolved obligations.
            deterministic_outcome = self.validation_pipeline.apply_deterministic_prevalidation(
                raw_issue,
                self.validation_pipeline.score_components(raw_issue, {}),
            )
            if deterministic_outcome is not None:
                conflict = bool(raw_issue.get("evidence_conflict"))
                if conflict:
                    authority = self._terminal_authority.evaluate(
                        raw_issue,
                        has_executable_action=True,
                    )
                    raw_issue["proof_conflict_resolution"] = deepcopy(
                        authority.conflict_resolution or {}
                    )
                    self._trace_event(
                        raw_issue,
                        stage="V0",
                        actor="deterministic_prevalidation",
                        reason_code="PROOF_CONFLICT",
                        output_refs=(evidence_ref,),
                        details={"action": deterministic_outcome.verdict},
                        dedupe_key=f"v0-conflict:{self._trace_cluster_uid(raw_issue)}",
                    )
                    resolution = authority.conflict_resolution or {}
                    if not bool(resolution.get("valid_positive")) or not bool(
                        resolution.get("valid_negative")
                    ):
                        self._trace_event(
                            raw_issue,
                            stage="V0",
                            actor="proof_conflict_resolver",
                            reason_code="PROOF_INVALID_SCOPE_OR_DEPENDENCY",
                            output_refs=(evidence_ref,),
                            details=deepcopy(resolution),
                            dedupe_key=(
                                f"v0-invalid-conflict-proof:"
                                f"{self._trace_cluster_uid(raw_issue)}"
                            ),
                        )
                    if authority.terminal and authority.disposition in {
                        "confirmed",
                        "rejected_with_proof",
                    }:
                        winner = str(resolution.get("winner") or "")
                        proof_key = (
                            "positive_decision_proof"
                            if winner == "positive"
                            else "negative_decision_proof"
                        )
                        raw_issue["decision_proof"] = deepcopy(raw_issue.get(proof_key) or {})
                        raw_issue["proof_coverage"] = "complete"
                        raw_issue["evidence_conflict"] = False
                        raw_issue["candidate_disposition"] = authority.disposition
                        raw_issue["validation_status"] = (
                            "validated" if authority.disposition == "confirmed" else "rejected"
                        )
                        raw_issue["terminal_authority_decision"] = authority.to_dict()
                        raw_issue["terminal_authority"] = authority.authority
                        raw_issue["terminal_reason_codes"] = [authority.reason_code]
                        resolved_outcome = ValidationOutcome(
                            report_bucket=(
                                "issues" if authority.disposition == "confirmed" else None
                            ),
                            memory_status=(
                                "validated" if authority.disposition == "confirmed" else "rejected"
                            ),
                            verdict=(
                                "verified" if authority.disposition == "confirmed" else "rejected"
                            ),
                            final_score=deterministic_outcome.final_score,
                        )
                        if resolved_outcome.report_bucket:
                            state[resolved_outcome.report_bucket].append(raw_issue)
                        self.remember_validation_result(
                            raw_issue, resolved_outcome.memory_status or "rejected"
                        )
                        self._update_candidate_ledger(state, raw_issue)
                        return None
                    # Both proofs remain valid under incompatible assumptions
                    # or paths.  Do not ask V1/V2 to vote; retain both and send
                    # exactly one cluster to targeted V3 when the selected
                    # scan depth supports it.
                    raw_issue["candidate_disposition"] = "needs_review"
                    raw_issue["validation_status"] = "needs_review"
                    raw_issue["proof_conflict_requires_v3"] = True
                else:
                    reason_code = (
                        "POSITIVE_PROOF_COMPLETE"
                        if deterministic_outcome.memory_status == "validated"
                        else (
                            "NEGATIVE_PROOF_COMPLETE"
                            if deterministic_outcome.memory_status == "rejected"
                            else "V0_UNRESOLVED"
                        )
                    )
                    self._trace_event(
                        raw_issue,
                        stage="V0",
                        actor="deterministic_prevalidation",
                        reason_code=reason_code,
                        output_refs=(evidence_ref,),
                        details={"verdict": deterministic_outcome.verdict},
                        dedupe_key=f"v0:{reason_code}:{self._trace_cluster_uid(raw_issue)}",
                    )
                if conflict:
                    return _PreparedValidation(
                        index=index,
                        raw_issue=raw_issue,
                        issue_func=issue_func,
                        issue_code=issue_code,
                        evidence_pack=evidence_pack,
                    )
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
                return None
        self._trace_event(
            raw_issue,
            stage="V0",
            actor="deterministic_prevalidation",
            reason_code="V0_UNRESOLVED",
            output_refs=(evidence_ref,),
            dedupe_key=f"v0-unresolved:{self._trace_cluster_uid(raw_issue)}",
        )
        _batch, fact_first_outcome = self._run_fact_first_prevalidation(
            raw_issue,
            evidence_pack,
        )
        if fact_first_outcome is not None:
            self._record_deterministic_prevalidation_outcome(
                state,
                raw_issue,
                fact_first_outcome,
            )
            if fact_first_outcome.report_bucket:
                state[fact_first_outcome.report_bucket].append(raw_issue)
            if fact_first_outcome.memory_status:
                self.remember_validation_result(raw_issue, fact_first_outcome.memory_status)
            self._update_candidate_ledger(state, raw_issue)
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
            if bool(item.raw_issue.get("proof_conflict_requires_v3")):
                token_metadata = self._empty_token_metadata()
                prior = self._terminal_uncertain_v3_result(
                    item,
                    {},
                    validation_pass="initial",
                    stop_reason="investigation_exhausted",
                    reasoning=(
                        "Two complete deterministic proofs remain valid under incompatible "
                        "paths or assumptions; only targeted conflict evidence may resolve them."
                    ),
                )
                if not item.allow_v3:
                    return _ValidationWorkerResult(
                        index=item.index,
                        raw_issue=item.raw_issue,
                        issue_func=item.issue_func,
                        success=True,
                        val_data=prior,
                        metadata=token_metadata,
                        evidence_pack=item.evidence_pack,
                    )
                validator_agent = validator_agent or self._build_validator_agent()
                val_data = self._run_v3_targeted_investigation(
                    item,
                    validator_agent,
                    prior,
                    token_metadata,
                )
                return _ValidationWorkerResult(
                    index=item.index,
                    raw_issue=item.raw_issue,
                    issue_func=item.issue_func,
                    success=True,
                    val_data=val_data,
                    metadata=token_metadata,
                    evidence_pack=item.evidence_pack,
                )
            cache_key = self._validator_cache_key(item)
            cached = self._validator_cache_get(cache_key)
            if cached is not None:
                metadata = self._empty_token_metadata()
                metadata["validator_cache_hit"] = 1
                self._trace_event(
                    item.raw_issue,
                    stage="V1",
                    actor="validation_result_cache",
                    reason_code="V1_COMPLETED",
                    details={"cache_hit": True, "verdict": validation_verdict(cached)},
                    dedupe_key=f"v1-cache:{cache_key}",
                )
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
                        metadata = self._empty_token_metadata()
                        metadata["validator_cache_hit"] = 1
                        metadata["validator_inflight_coalesced"] = 1
                        self._trace_event(
                            item.raw_issue,
                            stage="V1",
                            actor="validation_result_cache",
                            reason_code="V1_COMPLETED",
                            details={
                                "cache_hit": True,
                                "inflight_coalesced": True,
                                "verdict": validation_verdict(cached),
                            },
                            dedupe_key=f"v1-inflight-cache:{cache_key}",
                        )
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
            validator_input = self._validator_input(
                item.raw_issue, item.issue_code, item.evidence_pack
            )
            usage_start = len(self._cluster_usage_events(item.raw_issue))
            val_resp = validator_agent.run(validator_input)
            self._merge_response_metadata(token_metadata, getattr(val_resp, "metadata", {}) or {})

            if not val_resp.success:
                if not item.allow_v3 or not self._recoverable_v1_failure(val_resp):
                    self._record_model_trace(
                        item.raw_issue,
                        stage="V1",
                        structured_input=validator_input,
                        structured_output={
                            "protocol_failure": True,
                            "error_type": type(val_resp.error).__name__,
                        },
                        usage_start=usage_start,
                        reason_code="V1_COMPLETED",
                    )
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
                    reasoning=(
                        "The initial structured result was recoverably invalid; "
                        "targeted investigation may reconstruct the decision from evidence."
                    ),
                )
                item.raw_issue["validator_v1_recoverable_error"] = str(val_resp.error or "")[:500]
            else:
                val_data = self._normalize_worker_response(
                    item,
                    validator_agent,
                    val_resp.data,
                    token_metadata,
                )
            self._record_model_trace(
                item.raw_issue,
                stage="V1",
                structured_input=validator_input,
                structured_output=val_data,
                usage_start=usage_start,
                reason_code="V1_COMPLETED",
            )
            val_data = self._run_v3_evidence_recheck(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
            val_data = self._run_v3_targeted_investigation(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
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
        cached = self._validator_result_cache.get(cache_key)
        if cached is not None:
            if self._validator_result_is_cacheable(cached):
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
            self._validator_result_cache.put(cache_key, cached)
            return dict(cached)
        return None

    def _validator_cache_put(self, cache_key: str, val_data: Dict[str, Any]) -> bool:
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
        raw = getattr(analysis_cfg, "validation_deadline_seconds", 240)
        if raw is None:
            return None
        try:
            return max(1.0, float(raw))
        except (TypeError, ValueError):
            return 240.0

    def _validator_cache_key(self, item: _PreparedValidation) -> str:
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
            }
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
        stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

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
        self._accumulate_token_metadata(state, result.metadata)
        raw_issue = result.raw_issue
        if not result.success:
            self._handle_validation_failure(state, raw_issue, result.issue_func, result.error)
            self._update_candidate_ledger(state, raw_issue)
            return

        val_data = result.val_data
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
        authority = self._terminal_authority.evaluate(
            raw_issue,
            model_result=val_data,
            has_executable_action=False,
            protocol_or_engine_failure=False,
        )
        raw_issue["terminal_authority_decision"] = authority.to_dict()
        raw_issue["terminal_authority"] = authority.authority
        raw_issue["terminal_reason_codes"] = [authority.reason_code]
        if authority.disposition == "needs_review" and outcome.memory_status != "needs_review":
            raw_issue["candidate_disposition"] = "needs_review"
            raw_issue["validation_status"] = "needs_review"
            raw_issue["finding_kind"] = "needs_review"
            outcome = ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict="needs_review",
                final_score=outcome.final_score,
            )
        elif authority.disposition == "confirmed" and outcome.memory_status == "validated":
            raw_issue["candidate_disposition"] = "confirmed"
        elif authority.disposition == "rejected_with_proof":
            raw_issue["candidate_disposition"] = "rejected_with_proof"
            raw_issue["validation_status"] = "rejected"
            outcome = ValidationOutcome(
                report_bucket=None,
                memory_status="rejected",
                verdict="rejected",
                final_score=outcome.final_score,
            )
        raw_issue["policy_disposition"] = str(
            raw_issue.get("candidate_disposition") or outcome.memory_status or "needs_review"
        )
        self._record_validator_attribution(raw_issue, val_data, outcome)
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)
        if outcome.memory_status:
            self.remember_validation_result(raw_issue, outcome.memory_status)
        self._update_candidate_ledger(state, raw_issue)
        self._log_validation_outcome(raw_issue, val_data, verdict, outcome.final_score)

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
        issue["validator_policy_outcome"] = {
            "model_verdict": validation_verdict(val_data),
            "policy_disposition": policy_disposition,
            "decision_level": attribution["decision_level"],
        }

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

    @staticmethod
    def _update_candidate_ledger(
        state: Dict[str, Any],
        issue: Dict[str, Any],
    ) -> None:
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
            reasoning=(reasoning.strip() or "Validator work stopped before a final decision.")[
                :4000
            ],
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
        raw_request = val_data.get("missing_fact_request")
        requested_kind = (
            str(raw_request.get("fact_kind") or "").strip().lower()
            if isinstance(raw_request, Mapping)
            else ""
        )
        fact_first_attempted = {
            str(value)
            for value in item.raw_issue.get("fact_first_attempted_fact_kinds") or []
            if str(value)
        }
        if not requested_kind or requested_kind in fact_first_attempted:
            item.raw_issue["validator_fact_resolution"] = {
                "fact_kinds": [requested_kind] if requested_kind else [],
                "statuses": ["already_attempted"] if requested_kind else [],
                "status": "no_new_parameterized_request",
                "evidence_delta_hash": "",
                "proof_added": False,
            }
            item.raw_issue["validator_v2_stop_reason"] = "no_evidence_gain"
            self._trace_event(
                item.raw_issue,
                stage="V2",
                actor="validation_runner",
                reason_code="V2_SKIPPED_NO_DELTA",
                details={
                    "requested_fact_kind": requested_kind,
                    "fact_first_attempted": sorted(fact_first_attempted),
                },
                dedupe_key=(
                    f"v2-skipped-fact-first:{requested_kind or 'no-request'}:"
                    f"{self._trace_cluster_uid(item.raw_issue)}"
                ),
            )
            return val_data
        try:
            batch = self._evidence_completion_queue.resolve_required_facts(
                item.raw_issue,
                validator_data=val_data,
                validation_evidence=item.evidence_pack,
                fact_kinds_override=(requested_kind,),
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
                reasoning="The required deterministic fact providers failed.",
            )

        statuses = [value.terminal_status for value in batch.resolutions]
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
        resolution_ref = self._decision_trace_store.put_evidence(
            kind="fact_resolution_batch",
            payload={
                "resolutions": [
                    {
                        "fact_kind": value.fact_kind,
                        "status": value.status,
                        "terminal_status": value.terminal_status,
                        "miss_reason": value.miss_reason,
                    }
                    for value in batch.resolutions
                ],
                "evidence_delta": batch.evidence_delta,
                "evidence_delta_hash": batch.evidence_delta_hash,
                "proof_added": batch.proof_added,
            },
            producer="evidence_completion_queue",
        )
        for value in batch.resolutions:
            status = str(value.terminal_status or value.status or "").lower()
            reason_code = {
                "resolved": "FACT_VERIFIED_TRUE",
                "no_match": "PROVIDER_NO_MATCH",
                "unsupported": "FACT_UNKNOWN",
                "timeout": "PROVIDER_TIMEOUT",
                "provider_error": "PROVIDER_ERROR",
                "conflicting": "FACT_CONFLICTING",
                "duplicate_request": "FACT_UNKNOWN",
            }.get(status, "FACT_UNKNOWN")
            self._trace_event(
                item.raw_issue,
                stage="provider",
                actor="evidence_completion_queue",
                reason_code=reason_code,
                output_refs=(resolution_ref,),
                details={
                    "fact_kind": value.fact_kind,
                    "status": value.status,
                    "terminal_status": value.terminal_status,
                    "miss_reason": value.miss_reason,
                },
                dedupe_key=(
                    f"provider:{value.fact_kind}:{status}:"
                    f"{batch.evidence_delta_hash or 'no-delta'}"
                ),
            )
        if batch.proof_added:
            token_metadata["validator_fact_resolution_proof_count"] = (
                int(token_metadata.get("validator_fact_resolution_proof_count", 0) or 0) + 1
            )
            item.raw_issue["validator_v2_stop_reason"] = "decision_complete"
            proof_disposition = str(item.raw_issue.get("candidate_disposition") or "")
            self._trace_event(
                item.raw_issue,
                stage="provider",
                actor="terminal_authority_evaluator",
                reason_code=(
                    "NEGATIVE_PROOF_COMPLETE"
                    if proof_disposition == "rejected_with_proof"
                    else "POSITIVE_PROOF_COMPLETE"
                ),
                output_refs=(resolution_ref,),
                dedupe_key=f"fact-proof:{batch.evidence_delta_hash}",
            )
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                stop_reason="decision_complete",
                reasoning=(
                    "Required fact resolution produced a complete deterministic proof; "
                    "the policy layer owns the terminal disposition."
                ),
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
            self._trace_event(
                item.raw_issue,
                stage="V2",
                actor="validation_runner",
                reason_code="V2_SKIPPED_NO_DELTA",
                input_refs=(resolution_ref,),
                details={"stop_reason": stop_reason, "statuses": statuses},
                dedupe_key=f"v2-skipped:{stop_reason}:{self._trace_cluster_uid(item.raw_issue)}",
            )
            # Fact-first already attempted the immutable plan.  A repeated
            # no-delta batch after V1 is not a new model result and must not
            # overwrite a valid V1 verdict.  It only decides whether V2 is
            # skipped; TerminalAuthority and V3 eligibility consume the
            # unchanged result plus the explicit closure state.
            return val_data

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
                reasoning="The resolved fact set was already evaluated.",
            )
        previous_hashes.append(batch.evidence_delta_hash)

        validator_input = self._validator_input(
            item.raw_issue,
            item.issue_code,
            item.evidence_pack,
            validation_pass="evidence_recheck",
            evidence_delta=batch.evidence_delta,
        )
        usage_start = len(self._cluster_usage_events(item.raw_issue))
        response = validator_agent.run(validator_input)
        self._merge_response_metadata(token_metadata, getattr(response, "metadata", {}) or {})
        if not response.success or not isinstance(response.data, dict):
            item.raw_issue["validator_v2_stop_reason"] = "no_evidence_gain"
            if response.error:
                item.raw_issue["validator_v2_error"] = str(response.error)[:500]
            terminal = self._terminal_from_prior_for_v3(
                item,
                val_data,
                validation_pass="evidence_recheck",
                stop_reason="no_evidence_gain",
                reasoning="The V2 evidence recheck failed without a valid decision.",
            )
            self._record_model_trace(
                item.raw_issue,
                stage="V2",
                structured_input=validator_input,
                structured_output=terminal,
                usage_start=usage_start,
                reason_code="V2_COMPLETED",
            )
            return terminal
        revised = dict(response.data)
        if str(revised.get("schema_version") or "") != "zscope.validator-result.v3":
            item.raw_issue["validator_v2_stop_reason"] = "malformed_output"
            terminal = self._terminal_from_prior_for_v3(
                item,
                val_data,
                validation_pass="evidence_recheck",
                stop_reason="malformed_output",
                reasoning="The V2 evidence recheck returned a non-v3 result.",
            )
            self._record_model_trace(
                item.raw_issue,
                stage="V2",
                structured_input=validator_input,
                structured_output=terminal,
                usage_start=usage_start,
                reason_code="V2_COMPLETED",
            )
            return terminal
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
        self._record_model_trace(
            item.raw_issue,
            stage="V2",
            structured_input=validator_input,
            structured_output=revised,
            usage_start=usage_start,
            reason_code="V2_COMPLETED",
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
        remaining_fact_kinds = self._remaining_fact_kinds(item.raw_issue)
        actions = self._fact_capabilities.executable_actions(
            item.raw_issue,
            item.evidence_pack,
            remaining_fact_kinds,
        )
        if not remaining_fact_kinds or not actions:
            eligibility = item.raw_issue.get("validator_v3_eligibility")
            eligibility = dict(eligibility) if isinstance(eligibility, Mapping) else {}
            eligibility.update(
                {
                    "eligible": False,
                    "reason": "no_readonly_closable_gap",
                    "required_fact_kinds": list(remaining_fact_kinds),
                    "evidence_action_count": len(actions),
                }
            )
            item.raw_issue["validator_v3_eligibility"] = eligibility
            self._trace_event(
                item.raw_issue,
                stage="V3",
                actor="fact_capability_registry",
                reason_code="V3_NOT_ELIGIBLE_NO_EXECUTABLE_GAP",
                details=deepcopy(eligibility),
                dedupe_key=f"v3-no-action:{self._trace_cluster_uid(item.raw_issue)}",
            )
            return val_data
        item.raw_issue["validator_v3_entered"] = True
        self._trace_event(
            item.raw_issue,
            stage="V3",
            actor="validation_runner",
            reason_code="V3_ENTERED",
            details=deepcopy(item.raw_issue.get("validator_v3_eligibility") or {}),
            dedupe_key=f"v3-entered:{self._trace_cluster_uid(item.raw_issue)}",
        )
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
        usage_start = len(self._cluster_usage_events(item.raw_issue))
        fact_uids_before_v3 = {
            str(value.get("fact_uid") or "")
            for value in item.raw_issue.get("v3_investigation_facts") or []
            if isinstance(value, Mapping) and str(value.get("fact_uid") or "")
        }
        investigate_parameters = inspect.signature(investigate).parameters.values()
        supports_claim_verifier = any(
            parameter.name == "claim_verifier" for parameter in investigate_parameters
        )
        investigate_kwargs: Dict[str, Any] = {
            "max_iterations": item.v3_max_iterations or 50,
        }
        supports_evidence_actions = {
            parameter.name for parameter in inspect.signature(investigate).parameters.values()
        }.issuperset({"evidence_actions", "evidence_action_executor"})
        action_by_id = {value.action_id: value for value in actions}
        if supports_evidence_actions:

            def execute_evidence_action(action_id: str) -> Dict[str, Any]:
                action = action_by_id.get(str(action_id or ""))
                if action is None:
                    return {
                        "status": "unknown",
                        "reason_code": "unknown_evidence_action",
                        "verified_fact": None,
                    }
                remaining_before = set(self._remaining_fact_kinds(item.raw_issue))
                if action.fact_kind not in remaining_before:
                    authority = self._terminal_authority.evaluate(
                        item.raw_issue,
                        model_result=val_data,
                        has_executable_action=bool(
                            self._fact_capabilities.executable_actions(
                                item.raw_issue,
                                item.evidence_pack,
                                remaining_before,
                            )
                        ),
                    )
                    return {
                        "status": "unknown",
                        "reason_code": "evidence_action_clause_already_closed",
                        "verified_fact": None,
                        "newly_accepted": False,
                        "terminal_authority": authority.to_dict(),
                    }
                before_state = self._trace_state(item.raw_issue)
                result = self._function_ir_facts.execute(
                    action,
                    item.raw_issue,
                    item.evidence_pack,
                )
                certificate_ref = self._decision_trace_store.put_evidence(
                    kind="evidence_certificate_v2",
                    payload=result.certificate,
                    producer=action.verifier_id,
                    dependency_hashes=tuple(
                        str(value)
                        for value in (
                            result.certificate.get("code_snapshot_sha256"),
                            result.certificate.get("backend_sha256"),
                            result.certificate.get("function_ir_sha256"),
                        )
                        if str(value or "")
                    ),
                )
                fact = result.fact
                added = 0
                if isinstance(fact, dict):
                    added = self._apply_v3_investigation_facts(
                        item.raw_issue,
                        {"evidence_refs": [str(fact.get("fact_uid") or "")]},
                        {"validator_investigation_facts": [fact]},
                    )
                authority = self._terminal_authority.evaluate(
                    item.raw_issue,
                    model_result=val_data,
                    has_executable_action=bool(
                        self._fact_capabilities.executable_actions(
                            item.raw_issue,
                            item.evidence_pack,
                            self._remaining_fact_kinds(item.raw_issue),
                        )
                    ),
                )
                self._trace_event(
                    item.raw_issue,
                    stage="verifier",
                    actor=action.verifier_id,
                    reason_code={
                        "verified_true": "FACT_VERIFIED_TRUE",
                        "verified_false": "FACT_VERIFIED_FALSE",
                        "conflicting": "FACT_CONFLICTING",
                    }.get(result.status, "FACT_UNKNOWN"),
                    before_state=before_state,
                    output_refs=(certificate_ref,),
                    details={
                        "action_id": action.action_id,
                        "fact_kind": action.fact_kind,
                        "status": result.status,
                        "reason_code": result.reason_code,
                        "newly_accepted": bool(added),
                        "terminal_authority": authority.to_dict(),
                    },
                    dedupe_key=f"evidence-action:{action.action_id}",
                )
                payload = result.to_dict()
                payload["certificate_ref"] = certificate_ref
                payload["newly_accepted"] = bool(added)
                payload["terminal_authority"] = authority.to_dict()
                return payload

            investigate_kwargs["evidence_actions"] = [value.to_dict() for value in actions]
            investigate_kwargs["evidence_action_executor"] = execute_evidence_action
        if supports_claim_verifier:

            def verify_and_accept_claim(
                claim: Dict[str, Any],
                catalog: Mapping[str, Mapping[str, Any]],
            ) -> Dict[str, Any]:
                verification = self._verify_v3_claim(item.raw_issue, claim, catalog)
                fact = verification.get("verified_fact")
                if (
                    str(verification.get("status") or "") == "verified_true"
                    and isinstance(fact, dict)
                    and str(fact.get("fact_uid") or "")
                ):
                    before_state = self._trace_state(item.raw_issue)
                    added = self._apply_v3_investigation_facts(
                        item.raw_issue,
                        {"evidence_refs": [str(fact["fact_uid"])]},
                        {
                            "validator_investigation_facts": [fact],
                            "validator_tool_fact_catalog": dict(catalog),
                        },
                    )
                    authority = self._terminal_authority.evaluate(
                        item.raw_issue,
                        model_result=val_data,
                        has_executable_action=True,
                    )
                    verification = dict(verification)
                    verification["accepted_into_decision_slice"] = bool(
                        str(fact["fact_uid"])
                        in {
                            str(value)
                            for value in (item.raw_issue.get("decision_fact_slice") or {}).get(
                                "fact_uids", []
                            )
                            if str(value)
                        }
                    )
                    verification["newly_accepted"] = bool(added)
                    verification["evidence_closure_state"] = deepcopy(
                        item.raw_issue.get("evidence_closure_state") or {}
                    )
                    verification["terminal_authority"] = authority.to_dict()
                    self._trace_event(
                        item.raw_issue,
                        stage="policy",
                        actor="terminal_authority_evaluator",
                        reason_code="FACT_VERIFIED_TRUE",
                        before_state=before_state,
                        details={
                            "claim_uid": str(verification.get("claim_uid") or ""),
                            "fact_uid": str(fact["fact_uid"]),
                            "fact_kind": str(fact.get("fact_kind") or ""),
                            "newly_accepted": bool(added),
                            "terminal_authority": authority.to_dict(),
                        },
                        dedupe_key=f"accepted-v3-fact:{fact['fact_uid']}",
                    )
                return verification

            investigate_kwargs["claim_verifier"] = verify_and_accept_claim
        response = investigate(investigation_input, **investigate_kwargs)
        self._merge_response_metadata(
            token_metadata,
            getattr(response, "metadata", {}) or {},
        )
        if not response.success or not isinstance(response.data, dict):
            item.raw_issue["validator_v3_stop_reason"] = "investigation_exhausted"
            if response.error:
                item.raw_issue["validator_v3_error"] = str(response.error)[:500]
            terminal = self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="investigation_exhausted",
                reasoning="Targeted V3 investigation failed without a valid decision.",
            )
            self._record_model_trace(
                item.raw_issue,
                stage="V3",
                structured_input=investigation_input,
                structured_output=terminal,
                usage_start=usage_start,
                reason_code="V3_STOP_NO_REMAINING_ACTION",
            )
            return terminal
        revised = dict(response.data)
        if str(revised.get("schema_version") or "") != "zscope.validator-result.v3":
            item.raw_issue["validator_v3_stop_reason"] = "malformed_output"
            terminal = self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="malformed_output",
                reasoning="Targeted V3 investigation returned a non-v3 result.",
            )
            self._record_model_trace(
                item.raw_issue,
                stage="V3",
                structured_input=investigation_input,
                structured_output=terminal,
                usage_start=usage_start,
                reason_code="V3_STOP_NO_REMAINING_ACTION",
            )
            return terminal
        response_metadata = getattr(response, "metadata", {}) or {}
        tool_catalog = response_metadata.get("validator_tool_fact_catalog", {}) or {}
        tool_evidence_refs: List[str] = []
        if isinstance(tool_catalog, Mapping):
            for tool_fact_uid, raw_tool_fact in sorted(tool_catalog.items()):
                if not isinstance(raw_tool_fact, Mapping):
                    continue
                tool_evidence_refs.append(
                    self._decision_trace_store.put_evidence(
                        kind="v3_readonly_tool_result",
                        payload={
                            "tool_fact_uid": str(tool_fact_uid),
                            **deepcopy(dict(raw_tool_fact)),
                        },
                        producer="validator_agent_readonly_tool",
                    )
                )
        self._apply_v3_investigation_facts(
            item.raw_issue,
            revised,
            response_metadata,
        )
        fact_uids_after_v3 = {
            str(value.get("fact_uid") or "")
            for value in item.raw_issue.get("v3_investigation_facts") or []
            if isinstance(value, Mapping) and str(value.get("fact_uid") or "")
        }
        accepted_fact_count = len(fact_uids_after_v3 - fact_uids_before_v3)
        if accepted_fact_count:
            usage_ledger = getattr(self.config, "scan_token_usage_ledger", None)
            attribute_facts = getattr(usage_ledger, "attribute_accepted_facts", None)
            if callable(attribute_facts):
                attribute_facts(
                    validation_cluster_uid=str(item.raw_issue.get("validation_cluster_uid") or ""),
                    new_fact_count=accepted_fact_count,
                )
        revised = self._reconcile_v3_missing_fact(
            item,
            validator_agent,
            revised,
            token_metadata,
        )
        self._record_model_trace(
            item.raw_issue,
            stage="V3",
            structured_input=investigation_input,
            structured_output=revised,
            usage_start=usage_start,
            reason_code=(
                "V3_STOP_MAX_ITERATIONS"
                if int((getattr(response, "metadata", {}) or {}).get("iterations", 0) or 0)
                >= (item.v3_max_iterations or 50)
                else (
                    "V3_STOP_NO_PROGRESS"
                    if bool(
                        (getattr(response, "metadata", {}) or {}).get(
                            "validator_no_new_evidence_fact_stop"
                        )
                    )
                    else "V3_STOP_NO_REMAINING_ACTION"
                )
            ),
            tool_call_ids=tuple(str(value) for value in (tool_catalog) if str(value)),
            evidence_refs=tuple(tool_evidence_refs),
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
                "new_fact_count": accepted_fact_count,
            }
        )
        token_metadata["validator_targeted_investigation_count"] = (
            int(token_metadata.get("validator_targeted_investigation_count", 0) or 0) + 1
        )
        return revised

    def _verify_v3_claim(
        self,
        issue: Dict[str, Any],
        raw_claim: Dict[str, Any],
        tool_catalog: Mapping[str, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Recompute one model-proposed predicate over frozen tool payloads."""

        submission_ref = self._decision_trace_store.put_evidence(
            kind="model_evidence_claim_submission",
            payload=deepcopy(raw_claim),
            producer="validator_agent",
        )
        try:
            raw_fact_kind = str(raw_claim.get("fact_kind") or "").strip().lower()
            allowed_fact_kinds = set(
                self._evidence_completion_queue.required_resolution_fact_kinds(issue, {})
            )
            if allowed_fact_kinds and raw_fact_kind not in allowed_fact_kinds:
                raise ValueError(
                    "evidence claim fact_kind is outside the current obligation: "
                    f"{raw_fact_kind or '<empty>'}"
                )
            claim = EvidenceClaimRequest.from_mapping(
                raw_claim,
                default_obligation_uid=str(
                    issue.get("obligation_uid") or issue.get("candidate_uid") or ""
                ),
                default_subject_uid=str(
                    issue.get("subject_uid")
                    or issue.get("resource_identity")
                    or issue.get("resource_signature")
                    or ""
                ),
                default_decision_region_uid=str(issue.get("decision_region_uid") or ""),
            )
        except (TypeError, ValueError) as exc:
            claim_hash = self._stable_hash(raw_claim)
            claim_uid = "CLAIM_INVALID_" + claim_hash[:24]
            certificate = {
                "schema_version": "zscope.evidence-certificate.v1",
                "verifier_id": self._evidence_claim_verifier.verifier_id,
                "verifier_version": self._evidence_claim_verifier.verifier_version,
                "claim_uid": claim_uid,
                "status": "unknown",
                "reason": "claim_protocol_invalid",
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
            }
            certificate["certificate_sha256"] = hashlib.sha256(
                json.dumps(
                    certificate,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            certificate_ref = self._decision_trace_store.put_evidence(
                kind="evidence_verification_certificate",
                payload=certificate,
                producer=self._evidence_claim_verifier.verifier_id,
            )
            self._trace_event(
                issue,
                stage="verifier",
                actor=self._evidence_claim_verifier.verifier_id,
                reason_code="FACT_UNKNOWN",
                input_refs=(submission_ref,),
                output_refs=(certificate_ref,),
                details={
                    "claim_uid": claim_uid,
                    "fact_kind": str(raw_claim.get("fact_kind") or ""),
                    "predicate": str(raw_claim.get("predicate") or ""),
                    "verification_status": "unknown",
                    "verification_reason": "claim_protocol_invalid",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                },
                dedupe_key=f"invalid-claim:{claim_hash}",
            )
            return {
                "schema_version": "zscope.evidence-claim-verification.v1",
                "claim_uid": claim_uid,
                "status": "unknown",
                "reason_code": "claim_protocol_invalid",
                "fact_kind": str(raw_claim.get("fact_kind") or ""),
                "predicate": str(raw_claim.get("predicate") or ""),
                "polarity": str(raw_claim.get("polarity") or ""),
                "certificate": certificate,
                "verified_fact": None,
                "error": str(exc)[:500],
            }
        verification = self._evidence_claim_verifier.verify(
            claim,
            issue=issue,
            tool_catalog=tool_catalog,
        )
        tool_refs: List[str] = []
        for cited_ref in claim.cited_evidence_refs:
            record = tool_catalog.get(cited_ref)
            if not isinstance(record, Mapping):
                continue
            raw_location = record.get("location")
            locations = (dict(raw_location),) if isinstance(raw_location, Mapping) else ()
            tool_refs.append(
                self._decision_trace_store.put_evidence(
                    kind="validator_readonly_tool_result",
                    payload=dict(record),
                    producer=str(record.get("tool_name") or "validator_readonly_tool"),
                    dependency_hashes=(str(record.get("dependency_code_hash") or ""),),
                    locations=locations,
                )
            )
        claim_ref = self._decision_trace_store.put_evidence(
            kind="model_evidence_claim",
            payload=claim.to_dict(),
            producer="validator_agent",
        )
        certificate_ref = self._decision_trace_store.put_evidence(
            kind="evidence_verification_certificate",
            payload=verification.to_dict(),
            producer=self._evidence_claim_verifier.verifier_id,
            dependency_hashes=tuple(
                str(value)
                for value in verification.certificate.get("dependency_hashes") or []
                if str(value)
            ),
            locations=tuple(
                value
                for value in verification.certificate.get("locations") or []
                if isinstance(value, dict)
            ),
        )
        reason_code = {
            "verified_true": "FACT_VERIFIED_TRUE",
            "verified_false": "FACT_VERIFIED_FALSE",
            "conflicting": "FACT_CONFLICTING",
            "unknown": "FACT_UNKNOWN",
        }[verification.status]
        self._trace_event(
            issue,
            stage="verifier",
            actor=self._evidence_claim_verifier.verifier_id,
            reason_code=reason_code,
            input_refs=(submission_ref, claim_ref, *tool_refs),
            output_refs=(certificate_ref,),
            details={
                "claim_uid": claim.claim_uid,
                "fact_kind": claim.fact_kind,
                "predicate": claim.predicate,
                "polarity": claim.polarity,
                "verification_status": verification.status,
                "verification_reason": verification.reason_code,
            },
            dedupe_key=f"claim:{claim.claim_uid}:{verification.status}",
        )
        return verification.to_dict()

    def _reconcile_v3_missing_fact(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Close a new V3 fact request once, never with contradictory state."""

        raw_request = val_data.get("missing_fact_request")
        if not isinstance(raw_request, dict):
            return val_data
        fact_kind = str(raw_request.get("fact_kind") or "").strip().lower()
        if not fact_kind:
            return val_data
        missing = set(normalize_missing_fact_kinds(item.raw_issue.get("missing_fact_kinds") or []))
        missing.add(fact_kind)
        item.raw_issue["missing_fact_kinds"] = sorted(missing)
        fact_slice = item.raw_issue.get("decision_fact_slice")
        fact_slice = dict(fact_slice) if isinstance(fact_slice, dict) else {}
        fact_slice["missing_fact_kinds"] = sorted(missing)
        fact_slice["coverage"] = "partial"
        item.raw_issue["decision_fact_slice"] = fact_slice
        item.raw_issue["decision_fact_coverage"] = "partial"
        item.raw_issue["candidate_promotion_eligible"] = False
        item.raw_issue["candidate_promotion_reason"] = "v3_requested_additional_fact"
        item.raw_issue["v3_evidence_closure"] = {
            "complete": False,
            "reason": "v3_terminal_requested_additional_fact",
            "resolved_fact_kinds": list(
                (item.raw_issue.get("v3_evidence_closure") or {}).get("resolved_fact_kinds", [])
            ),
            "remaining_fact_kinds": sorted(missing),
        }
        try:
            batch = self._evidence_completion_queue.resolve_required_facts(
                item.raw_issue,
                validator_data=val_data,
                validation_evidence=item.evidence_pack,
            )
        except Exception as exc:
            item.raw_issue["validator_v3_post_resolution"] = {
                "status": "provider_error",
                "fact_kind": fact_kind,
                "error": f"{type(exc).__name__}: {exc}"[:500],
            }
            return self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="unsupported_fact",
                reasoning="The V3 terminal fact request could not be resolved deterministically.",
            )
        item.raw_issue["validator_v3_post_resolution"] = {
            "status": str(item.raw_issue.get("evidence_completion_status") or "no_match"),
            "fact_kind": fact_kind,
            "evidence_delta_hash": batch.evidence_delta_hash,
            "proof_added": batch.proof_added,
            "resolution_statuses": [
                {
                    "fact_kind": value.fact_kind,
                    "status": value.terminal_status,
                    "miss_reason": value.miss_reason,
                }
                for value in batch.resolutions
            ],
        }
        closure = item.raw_issue.get("evidence_closure_state")
        if isinstance(closure, dict):
            fact_slice = item.raw_issue.get("decision_fact_slice")
            fact_slice = fact_slice if isinstance(fact_slice, dict) else {}
            item.raw_issue["v3_evidence_closure"] = {
                "complete": bool(closure.get("complete")),
                "reason": (
                    "post_v3_deterministic_fact_closure"
                    if closure.get("complete")
                    else "post_v3_fact_request_still_open"
                ),
                "resolved_fact_kinds": list(closure.get("resolved_fact_kinds") or []),
                "remaining_fact_kinds": list(closure.get("missing_fact_kinds") or []),
                "conflicting_fact_kinds": list(closure.get("conflicting_fact_kinds") or []),
                "fact_uids": list(fact_slice.get("fact_uids") or []),
                "closure_hash": str(closure.get("closure_hash") or ""),
            }
        if batch.proof_added:
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="decision_complete",
                reasoning=(
                    "The final V3 fact request produced a complete deterministic proof; "
                    "the policy layer owns the disposition."
                ),
            )
        if not batch.has_evidence_delta:
            return self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="no_evidence_gain",
                reasoning="The final V3 fact request produced no new deterministic evidence.",
            )
        response = validator_agent.run(
            self._validator_input(
                item.raw_issue,
                item.issue_code,
                item.evidence_pack,
                validation_pass="investigation_synthesis",
                evidence_delta=batch.evidence_delta,
            )
        )
        self._merge_response_metadata(token_metadata, getattr(response, "metadata", {}) or {})
        if not response.success or not isinstance(response.data, dict):
            return self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="no_evidence_gain",
                reasoning="The final V3 evidence synthesis did not return a valid decision.",
            )
        revised = dict(response.data)
        if str(revised.get("schema_version") or "") != "zscope.validator-result.v3":
            return self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="malformed_output",
                reasoning="The final V3 evidence synthesis returned a non-v3 result.",
            )
        return revised

    def _model_result_requires_review(
        self,
        item: _PreparedValidation,
        val_data: Dict[str, Any],
    ) -> bool:
        """Use the same terminal authority that owns the final disposition."""

        probe = deepcopy(item.raw_issue)
        score_data = self.validation_pipeline.score_components(probe, val_data)
        outcome = self.validation_pipeline.apply_validator_result(
            probe,
            val_data,
            verdict=validation_verdict(val_data),
            score_data=score_data,
        )
        authority = self._terminal_authority.evaluate(
            probe,
            model_result=val_data,
            # This method is called only after the caller established that V3
            # has an executable, read-only evidence gap.
            has_executable_action=True,
            protocol_or_engine_failure=outcome.memory_status == "engine_failed",
        )
        if not authority.terminal:
            return True
        return authority.disposition == "needs_review" or outcome.memory_status in {
            "needs_review",
            "engine_failed",
        }

    @staticmethod
    def _apply_v3_investigation_facts(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> int:
        """Bind every program-verified V3 claim into the decision fact slice.

        A model terminal must still cite a verified FACT before a ``verified``
        verdict can be promoted. Citation is not what makes the fact
        authoritative: the independent verifier certificate is. Persisting a
        verified fact immediately lets later V3 turns consume the new closure
        state and makes ``new_fact_count`` describe system-accepted evidence.
        """

        raw_facts = metadata.get("validator_investigation_facts")
        facts = [dict(value) for value in raw_facts or [] if isinstance(value, dict)]
        raw_tool_catalog = metadata.get("validator_tool_fact_catalog")
        incoming_tool_catalog = (
            {
                str(uid): dict(record)
                for uid, record in raw_tool_catalog.items()
                if str(uid) and isinstance(record, dict)
            }
            if isinstance(raw_tool_catalog, dict)
            else {}
        )
        existing_tool_catalog = issue.get("v3_tool_fact_catalog")
        tool_catalog = (
            {
                str(uid): dict(record)
                for uid, record in existing_tool_catalog.items()
                if str(uid) and isinstance(record, dict)
            }
            if isinstance(existing_tool_catalog, dict)
            else {}
        )
        tool_catalog.update(incoming_tool_catalog)
        cited = {
            str(value)
            for value in val_data.get("evidence_refs") or []
            if isinstance(value, str) and value
        }
        verified_facts = []
        cited_verified_facts = []
        for fact in facts:
            fact_uid = str(fact.get("fact_uid") or "")
            backing_refs = fact.get("evidence_refs")
            backing_refs = (
                [str(value) for value in backing_refs if str(value)]
                if isinstance(backing_refs, list)
                else []
            )
            locations = fact.get("locations")
            certificate = fact.get("verification_certificate")
            certificate_valid = False
            certificate_v2_valid = False
            if isinstance(certificate, dict):
                certificate_valid, _ = verify_evidence_certificate(certificate)
                certificate_v2_valid = verify_certificate_v2(certificate)
            tool_payloads_valid = True
            for ref in backing_refs:
                record = tool_catalog.get(ref)
                if not isinstance(record, dict):
                    tool_payloads_valid = False
                    break
                payload = record.get("result_payload")
                expected_hash = str(record.get("result_hash") or "")
                if not isinstance(payload, dict) or not expected_hash:
                    tool_payloads_valid = False
                    break
                actual_hash = hashlib.sha256(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        default=str,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                if actual_hash != expected_hash:
                    tool_payloads_valid = False
                    break
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
            legacy_valid = (
                issue.get("allow_legacy_v3_claim_replay") is True
                and str(fact.get("producer_engine") or "")
                == "zscope.structured-tool-claim-verifier"
                and str(fact.get("verification_status") or "") == "verified_true"
                and certificate_valid
                and isinstance(certificate, dict)
                and str(certificate.get("status") or "") == "verified_true"
                and str(certificate.get("fact_kind") or "") == str(fact.get("fact_kind") or "")
                and str(fact.get("dependency_code_hash") or "")
                and backing_refs
                and all(ref in tool_catalog for ref in backing_refs)
                and tool_payloads_valid
                and has_locations
            )
            certificate_action_valid = (
                certificate_v2_valid
                and isinstance(certificate, dict)
                and str(certificate.get("status") or "") == "verified_true"
                and certificate.get("quantifier_coverage_complete") is True
                and str(certificate.get("fact_kind") or "") == str(fact.get("fact_kind") or "")
                and str(certificate.get("provider_id") or "")
                == str(fact.get("provider_id") or fact.get("producer_engine") or "")
                and str(fact.get("dependency_code_hash") or "")
                and has_locations
            )
            if legacy_valid or certificate_action_valid:
                verified_facts.append(fact)
                if fact_uid in cited:
                    cited_verified_facts.append(fact)
        issue["v3_tool_fact_catalog"] = tool_catalog
        existing = issue.setdefault("v3_investigation_facts", [])
        if not isinstance(existing, list):
            existing = []
            issue["v3_investigation_facts"] = existing
        known = {str(value.get("fact_uid") or "") for value in existing if isinstance(value, dict)}
        added = 0
        for fact in verified_facts:
            uid = str(fact.get("fact_uid") or "")
            if uid and uid not in known:
                existing.append(fact)
                known.add(uid)
                added += 1
                proof = fact.get("deterministic_proof")
                if isinstance(proof, Mapping):
                    existing_proofs = issue.setdefault("deterministic_proofs", [])
                    if not isinstance(existing_proofs, list):
                        existing_proofs = []
                        issue["deterministic_proofs"] = existing_proofs
                    proof_identity = (
                        str(proof.get("outcome") or ""),
                        str(proof.get("proof_kind") or ""),
                        str(proof.get("certificate_sha256") or ""),
                    )
                    known_proofs = {
                        (
                            str(value.get("outcome") or ""),
                            str(value.get("proof_kind") or ""),
                            str(value.get("certificate_sha256") or ""),
                        )
                        for value in existing_proofs
                        if isinstance(value, Mapping)
                    }
                    if proof_identity not in known_proofs:
                        existing_proofs.append(dict(proof))
        all_verified_facts = [dict(value) for value in existing if isinstance(value, dict)]
        issue["v3_investigation_fact_count"] = len(all_verified_facts)
        issue["v3_investigation_cited_fact_count"] = len(cited_verified_facts)
        if not all_verified_facts:
            issue["v3_evidence_closure"] = {
                "complete": False,
                "reason": "no_program_verified_fact",
                "resolved_fact_kinds": [],
            }
            return 0

        fact_slice = issue.get("decision_fact_slice")
        fact_slice = dict(fact_slice) if isinstance(fact_slice, dict) else {}
        raw_missing = issue.get("missing_fact_kinds") or fact_slice.get("missing_fact_kinds") or []
        missing = set(normalize_missing_fact_kinds(raw_missing))
        resolved = {
            str(value)
            for fact in all_verified_facts
            for value in fact.get("satisfies_fact_kinds") or []
            if str(value)
        }
        remaining = sorted(missing - resolved)
        fact_uids = {str(value) for value in fact_slice.get("fact_uids") or [] if str(value)}
        fact_payloads = [
            dict(value) for value in fact_slice.get("facts") or [] if isinstance(value, dict)
        ]
        known_payloads = {
            str(value.get("fact_uid") or value.get("uid") or value.get("id") or "")
            for value in fact_payloads
        }
        for fact in all_verified_facts:
            uid = str(fact.get("fact_uid") or "")
            if uid and uid not in known_payloads:
                fact_payloads.append(dict(fact))
                known_payloads.add(uid)
        fact_uids.update(
            str(fact.get("fact_uid")) for fact in all_verified_facts if fact.get("fact_uid")
        )
        code_hashes = {
            str(value) for value in fact_slice.get("dependency_code_hashes") or [] if str(value)
        }
        code_hashes.update(
            str(fact.get("dependency_code_hash"))
            for fact in all_verified_facts
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
        existing_closure = issue.get("evidence_closure_state")
        existing_closure = dict(existing_closure) if isinstance(existing_closure, Mapping) else {}
        security_obligation = issue.get("security_obligation")
        security_obligation = (
            dict(security_obligation) if isinstance(security_obligation, Mapping) else {}
        )
        required = set(
            normalize_missing_fact_kinds(
                existing_closure.get("required_fact_kinds")
                or issue.get("obligation_required_fact_kinds")
                or security_obligation.get("required_fact_kinds")
                or sorted(missing | resolved)
            )
        )
        resolved.update(
            normalize_missing_fact_kinds(existing_closure.get("resolved_fact_kinds") or [])
        )
        conflicting = set(
            normalize_missing_fact_kinds(existing_closure.get("conflicting_fact_kinds") or [])
        )
        remaining = sorted(required - resolved)
        complete = bool(required and not remaining and not conflicting and code_hashes)
        fact_slice["missing_fact_kinds"] = remaining
        fact_slice["coverage"] = "complete" if complete else "partial"
        issue["decision_fact_slice"] = fact_slice
        issue["missing_fact_kinds"] = remaining
        issue["decision_fact_coverage"] = fact_slice["coverage"]
        closure_payload = {
            "required": sorted(required),
            "resolved": sorted(resolved),
            "missing": remaining,
            "conflicting": sorted(conflicting),
            "decision_fact_coverage": "complete" if complete else "partial",
        }
        closure_hash = hashlib.sha256(
            json.dumps(
                closure_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        issue["evidence_closure_state"] = {
            "schema_version": "zscope.evidence-closure-state.v1",
            "required_fact_kinds": sorted(required),
            "resolved_fact_kinds": sorted(resolved),
            "missing_fact_kinds": remaining,
            "conflicting_fact_kinds": sorted(conflicting),
            "complete": complete,
            "closure_hash": closure_hash,
        }
        issue["v3_evidence_closure"] = {
            "complete": complete,
            "reason": "required_facts_closed" if complete else "required_facts_still_missing",
            "resolved_fact_kinds": sorted(resolved),
            "remaining_fact_kinds": remaining,
            "fact_uids": sorted(
                str(fact.get("fact_uid")) for fact in all_verified_facts if fact.get("fact_uid")
            ),
        }
        if complete:
            issue["candidate_promotion_eligible"] = True
            issue["candidate_promotion_reason"] = "v3_tool_evidence_complete"
        else:
            issue["candidate_promotion_eligible"] = False
            issue["candidate_promotion_reason"] = (
                "v3_tool_evidence_conflicting" if conflicting else "v3_tool_evidence_incomplete"
            )
        return added

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
        raw_issue["terminal_authority"] = "validation_engine"
        raw_issue["terminal_reason_codes"] = ["NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE"]
        self._trace_event(
            raw_issue,
            stage="policy",
            actor="validation_engine",
            reason_code="NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",
            details={"error": f"{type(error).__name__}: {error}"[:500]},
            dedupe_key=f"engine-failure:{self._trace_cluster_uid(raw_issue)}",
        )
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
        if not self._looks_like_external_api(issue_func):
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
                self._record_issue_function_normalization(raw_issue, issue_func, fallback)
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

    @classmethod
    def _looks_like_external_api(cls, func_name: str) -> bool:
        cleaned = str(func_name or "").strip()
        if cleaned in cls._EXTERNAL_API_NAMES:
            return True
        return cleaned.startswith(("VOS_", "vos_", "osal_", "OSAL_")) and any(
            token in cleaned.lower()
            for token in ("alloc", "free", "mem", "taskcreate", "thread", "lock", "unlock")
        )

    @staticmethod
    def _record_issue_function_normalization(
        raw_issue: Dict[str, Any],
        original_func: str,
        normalized_func: str,
    ) -> None:
        raw_issue.setdefault("sink_function", original_func)
        raw_issue["validation_function_normalized_from"] = original_func
        raw_issue["validation_function_normalization_reason"] = (
            "external_api_function_without_indexed_body"
        )
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
            obligation = _as_dict(evidence_slice.get("obligation"))
            obligation["candidate_uid"] = finding_uid
            obligation["validation_cluster_uid"] = validation_cluster_uid
            evidence_slice = self._fit_validator_slice(evidence_slice, max_tokens=12_000)
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
            return val_input

        val_input = {
            "finding": json.dumps(
                compact_validation_finding(raw_issue),
                indent=2,
                ensure_ascii=False,
            ),
            "context_code": trim_code(issue_code, max_lines=180),
            "evidence_pack": compact_validation_evidence_pack(evidence_pack),
        }
        self.attach_agent_contract(val_input, "validator_agent")
        return val_input

    @staticmethod
    def _fit_validator_slice(
        evidence_slice: Dict[str, Any],
        *,
        max_tokens: int,
    ) -> Dict[str, Any]:
        """Bound user evidence while preserving IDs and decision commitments."""

        def estimate() -> int:
            payload = json.dumps(
                evidence_slice,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            return LLMClient.estimate_tokens([{"role": "user", "content": payload}])

        if estimate() <= max_tokens:
            return evidence_slice
        evidence_slice["slice_truncated"] = True
        evidence_slice["slice_truncated_sections"] = []
        code = _as_dict(evidence_slice.get("code"))
        function_context = str(code.get("function_context") or "")
        lines = function_context.splitlines()
        while len(lines) > 32 and estimate() > max_tokens:
            lines = lines[: max(32, len(lines) // 2)]
            code["function_context"] = "\n".join(lines)
        if len(lines) < len(function_context.splitlines()):
            evidence_slice["slice_truncated_sections"].append("function_context")
        for key, floor in (("semantic_claims", 4),):
            values = evidence_slice.get(key)
            if isinstance(values, list) and len(values) > floor and estimate() > max_tokens:
                evidence_slice[key] = values[:floor]
                evidence_slice["slice_truncated_sections"].append(key)
        decision = _as_dict(evidence_slice.get("decision_facts"))
        facts = decision.get("facts")
        if isinstance(facts, list) and len(facts) > 12 and estimate() > max_tokens:
            decision["facts"] = facts[:12]
            evidence_slice["slice_truncated_sections"].append("decision_facts.facts")
        if estimate() > max_tokens:
            for key in ("callers", "callees", "snapshot_summary"):
                if code.get(key) and estimate() > max_tokens:
                    code[key] = [] if key != "snapshot_summary" else {}
                    evidence_slice["slice_truncated_sections"].append(f"code.{key}")
        if estimate() > max_tokens:
            code["location_snippet"] = None
            evidence_slice["semantic_claims"] = []
            requirements = evidence_slice.get("validation_requirements")
            if isinstance(requirements, list):
                evidence_slice["validation_requirements"] = requirements[:4]
            catalog = evidence_slice.get("evidence_ref_catalog")
            if isinstance(catalog, dict):
                for value in catalog.values():
                    if isinstance(value, dict):
                        value["summary"] = ""
            evidence_slice["slice_truncated_sections"].extend(
                ["code.location_snippet", "semantic_claims", "evidence_ref_catalog.summary"]
            )
        if estimate() > max_tokens:
            code["function_context"] = "\n".join(
                str(code.get("function_context") or "").splitlines()[:16]
            )
            facts = decision.get("facts")
            if isinstance(facts, list):
                decision["facts"] = facts[:4]
            evidence = _as_dict(evidence_slice.get("evidence"))
            for key in ("positive", "negative", "path_constraints"):
                values = evidence.get(key)
                if isinstance(values, list):
                    evidence[key] = [str(value)[:400] for value in values[:4]]
            evidence_slice["slice_truncated_sections"].append("minimal_decision_projection")
        evidence_slice["slice_estimated_tokens"] = estimate()
        if int(evidence_slice["slice_estimated_tokens"]) > max_tokens:
            raise ValueError(
                "Validator evidence identifiers exceed the 12K-token v3 input allowance."
            )
        return evidence_slice

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
