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

from ...agents.proof_engine.agent import ProofEngineAgent
from ...common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from ...common.issue_identity import canonical_issue_key, deduplicate_issues
from ...config.function_entry import FunctionEntry
from ...framework.llm_client import LLMClient, ProviderFailureError
from ...framework.llm_usage import (
    P6BalancedTokenAdmissionError,
    llm_usage_attribution_scope,
)
from ...orchestration.scheduler import VALIDATOR_ROLE, ScanScheduler
from ...orchestration.decision_trace import DecisionTraceError, ensure_decision_trace_store
from ...orchestration.candidate_envelope import (
    CANDIDATE_SCHEMA_VERSION,
    DECISION_CONTEXT_VERSION,
)
from ...orchestration.runtime_authority import RUNTIME_CACHE_EPOCH
from ...orchestration.proof_promotion_qualification import (
    load_runtime_successor_qualification as load_successor_qualification,
)
from ...orchestration.successor_runtime_review_status import (
    SUCCESSOR_RUNTIME_REVIEW_MANIFEST,
    validate_current_successor_runtime_review_status,
    validate_successor_runtime_review_status,
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
    parse_validator_result_v3,
    validator_result_schema_v3,
)


def _as_dict(value: Any) -> Dict[str, Any]:
    """Narrow dynamic validation payloads while preserving their identity."""
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


from .pipeline import ValidationOutcome, ValidationPipeline
from .audit_eligibility import (
    evaluate_audit_eligibility,
    has_exact_v4_producer_occurrence_binding,
    revalidate_v4_producer_occurrence_binding,
)
from .evidence_completion import EvidenceCompletionQueue
from .fact_capabilities import (
    EvidenceAction,
    FactCapabilityRegistry,
    FunctionIRFactService,
    verify_certificate_v2,
)
from .authority import (
    TERMINAL_AUTHORITY_DECISION_V4,
    AuthorityOperation,
    TerminalAuthorityDecision,
    TerminalAuthorityEvaluator,
)
from .proof_kernel.lifecycle import PROOF_KERNEL_MODE
from .proof_kernel.engine import PROOF_KERNEL_AUTHORITY_INPUT_VERSION, ProofKernelEngine
from .proof_kernel.canonical import content_sha256

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
    admission_failure_class: str = ""
    admission_request_denied: bool = False
    provider_failure_class: str = ""


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

    # P5 intentionally severs every pre-authority validation cache lineage.
    _VALIDATION_CACHE_PROTOCOL_PREFIX = (
        f"{RUNTIME_CACHE_EPOCH}.proof-engine-cache.successor-bound.v2"
    )
    _DEFAULT_VALIDATION_CACHE_SIZE = 4096
    # Internal lifecycle identity only; there is no user-selectable authority switch.
    _PROOF_KERNEL_TERMINAL_MODE = PROOF_KERNEL_MODE
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
        proof_engine_agent_factory: Callable[..., Any] = ProofEngineAgent,
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
        self.proof_engine_agent_factory = proof_engine_agent_factory
        self.scheduler = scheduler
        # A fixed epoch is insufficient after a deterministic successor is
        # regenerated within the same broad runtime protocol.  Persisted and
        # in-flight Validator results must bind both the exact implementation
        # root, answer-free qualification, and current review projection.
        try:
            successor = load_successor_qualification()
            implementation_root = str(successor["implementation_root_sha256"])
            qualification_sha256 = str(successor["content_sha256"])
            review_status = dict(SUCCESSOR_RUNTIME_REVIEW_MANIFEST)
            valid_review, review_reason = validate_successor_runtime_review_status(
                review_status,
                expected_implementation_root_sha256=implementation_root,
                expected_successor_qualification_sha256=qualification_sha256,
            )
            if not valid_review:
                raise ValueError(review_reason)
            current_review, current_reason = validate_current_successor_runtime_review_status(
                review_status
            )
            if review_status.get("status") == "reviewed":
                if not current_review:
                    raise ValueError(current_reason)
            elif current_review or current_reason != "successor_review_in_progress":
                raise ValueError(current_reason)
            successor_cache_binding = {
                "successor_implementation_root_sha256": implementation_root,
                "successor_qualification_sha256": qualification_sha256,
                "successor_review_status": str(review_status["status"]),
                "successor_review_status_content_sha256": str(review_status["content_sha256"]),
                "successor_review_set_sha256": str(review_status["review_set_sha256"]),
            }
        except (KeyError, OSError, TypeError, ValueError):
            # Development or a partially installed package may not yet carry
            # a fresh qualification.  Analysis can still fail closed into a
            # non-release report, but no persisted result may cross that
            # boundary.  In-memory coalescing remains scoped to this runner.
            self._validation_cache_protocol = (
                self._VALIDATION_CACHE_PROTOCOL_PREFIX + ".unqualified"
            )
            self._validation_cache_successor_binding = {}
            self._validation_persistent_cache_enabled = False
        else:
            self._validation_cache_successor_binding = successor_cache_binding
            binding_sha256 = self._stable_hash(successor_cache_binding)
            self._validation_cache_protocol = ".".join(
                (self._VALIDATION_CACHE_PROTOCOL_PREFIX, binding_sha256)
            )
            self._validation_persistent_cache_enabled = True
        # Validator verdicts are contextual.  Keeping this cache on the runner
        # scopes it to one immutable scan instead of leaking decisions between
        # projects, revisions, entries, or long-lived service requests.
        self._validator_result_cache_size = self._validation_cache_size()
        self._validator_result_cache = result_cache or ValidationResultCache(
            self._validator_result_cache_size
        )
        self._validation_prompt_contract = self._build_validation_prompt_contract()
        self._validation_prompt_contract_sha256 = self._stable_hash(
            self._validation_prompt_contract
        )
        self._validation_environment_fingerprint = self._build_validation_environment_fingerprint()
        compile_commands_path = getattr(code_index, "compile_commands_path", None)
        ir_enabled = self._scan_depth() in {"balanced", "deep"}
        self._function_ir_facts = FunctionIRFactService(
            Path(compile_commands_path) if compile_commands_path else None,
            enabled=ir_enabled,
            code_index=code_index,
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
        # Stable V0 compatibility is deliberately isolated from the strict
        # post-V1 fact queue.  Reusing one queue made legacy bounded providers
        # look like a new V2 delta and changed the validation state machine.
        self._compatibility_prevalidation_queue = EvidenceCompletionQueue(
            enabled=True,
            max_workers=config.concurrency.evidence_completion_workers,
            enable_v11_providers=True,
            enable_v12_providers=True,
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
                "prompt_contract_sha256": self._validation_prompt_contract_sha256,
            }
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
        required: bool = False,
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
                require_persistence=required,
            )
        except Exception:
            if required:
                raise
            logger.warning(
                "Decision trace append failed for %s class=%s",
                cluster_uid,
                "decision_trace_append_failed",
            )

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
        all_call_ids = tuple(
            str(value.get("call_id") or "") for value in events if value.get("call_id")
        )
        cluster_uid = self._trace_cluster_uid(issue)
        bound_call_ids = self._decision_trace_store.bound_call_ids(cluster_uid)
        call_ids = tuple(value for value in all_call_ids if value not in bound_call_ids)
        token_delta = sum(
            int(value.get("total_tokens") or 0)
            for value in events
            if str(value.get("call_id") or "") in call_ids
        )
        bound_tool_call_ids = self._decision_trace_store.bound_tool_call_ids(cluster_uid)
        trace_tool_call_ids = tuple(
            value for value in tool_call_ids if value not in bound_tool_call_ids
        )
        ref = self._decision_trace_store.put_model_event(
            call_identity=f"{cluster_uid}:{stage}:{usage_start}",
            stage=stage,
            validation_cluster_uid=cluster_uid,
            structured_input=structured_input,
            structured_output=structured_output,
            call_ids=all_call_ids,
            tool_call_ids=tool_call_ids,
            prompt_revision=VALIDATOR_PROTOCOL_V3,
            prompt_hash=self._rendered_validation_prompt_schema_sha256(structured_input),
        )
        self._trace_event(
            issue,
            stage=stage,
            actor="proof_engine",
            reason_code=reason_code,
            output_refs=(ref, *evidence_refs),
            call_ids=call_ids,
            tool_call_ids=trace_tool_call_ids,
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

        prepared = []
        for index, raw_issue in enumerate(new_issues):
            item = self._prepare_issue_for_validation(state, raw_issue, index)
            if item is not None:
                prepared.append(item)

        if not self._validator_enabled():
            self._mark_unvalidated(state, [item.raw_issue for item in prepared])
            state["pending_new_issues"] = []
            state["validation_queue_drained"] = True
            return

        prepared = self._assign_v3_investigation_budget(prepared)
        prepared = self._order_balanced_validation_work(prepared)

        if self._scan_depth() == "fast":
            for item in prepared:
                self._close_open_checker_outcome_without_model(state, item.raw_issue)
            state["pending_new_issues"] = []
            state["validation_queue_drained"] = True
            return

        validation_workers = self._validation_worker_count(len(prepared))
        parent_token = current_cancellation_token()
        if parent_token is not None:
            parent_token.raise_if_cancelled()
        if validation_workers <= 1 and self.scheduler is None:
            validator_agent = self._build_proof_engine_agent() if prepared else None
            for position, item in enumerate(prepared):
                if parent_token is not None:
                    parent_token.raise_if_cancelled()
                self._mark_validation_running(state, item.raw_issue)
                result = self._validate_with_deadline(
                    item,
                    parent_token=parent_token,
                    validator_agent=validator_agent,
                )
                self._apply_validation_worker_result(state, result)
                if result.provider_failure_class:
                    state["pending_new_issues"] = [
                        pending.raw_issue for pending in prepared[position:]
                    ]
                    state["validation_provider_failure_batch_admitted_count"] = 1
                    state["validation_provider_failure_batch_settled_count"] = 1
                    state["validation_provider_failure_unstarted_count"] = max(
                        0, len(prepared) - position - 1
                    )
                    state["validation_queue_drained"] = False
                    raise ProviderFailureError(result.provider_failure_class)
                if result.admission_failure_class == "p6_token_hard_limit":
                    for unstarted in prepared[position + 1 :]:
                        self._apply_validation_worker_result(
                            state,
                            _ValidationWorkerResult(
                                index=unstarted.index,
                                raw_issue=unstarted.raw_issue,
                                issue_func=unstarted.issue_func,
                                success=False,
                                error="p6_token_hard_limit",
                                evidence_pack=dict(unstarted.evidence_pack),
                                admission_failure_class="p6_token_hard_limit",
                            ),
                        )
                    break
        elif prepared:
            logger.info(
                "Validating %d issue(s) with %d validator worker(s).",
                len(prepared),
                validation_workers,
            )
            results: Dict[int, _ValidationWorkerResult] = {}
            executor: Optional[ThreadPoolExecutor] = None
            hard_cancelled = False
            provider_failure_class = ""
            future_to_item: Dict[Future[Any], _PreparedValidation] = {}
            if self.scheduler is None:
                executor = ThreadPoolExecutor(
                    max_workers=validation_workers,
                    thread_name_prefix="zscope-validator",
                )
            try:
                for batch_start in range(0, len(prepared), validation_workers):
                    batch = prepared[batch_start : batch_start + validation_workers]
                    future_to_item = {}
                    for item in batch:
                        if parent_token is not None:
                            parent_token.raise_if_cancelled()
                        if self.scheduler is not None:
                            future = self.scheduler.submit(
                                VALIDATOR_ROLE,
                                self._validate_with_deadline,
                                item,
                                parent_token=parent_token,
                                priority=self._balanced_scheduler_priority(item),
                            )
                        else:
                            assert executor is not None
                            future = executor.submit(
                                self._validate_with_deadline,
                                item,
                                parent_token=parent_token,
                            )
                        self._mark_validation_running(state, item.raw_issue)
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
                            except P6BalancedTokenAdmissionError:
                                # Admission is handled inside
                                # ``_validate_with_deadline``.  If it ever
                                # escapes, it must not be relabeled as a
                                # validation worker crash.
                                hard_cancelled = True
                                self._cancel_validation_futures(pending)
                                raise
                            except ProviderFailureError as exc:
                                # ``_validate_with_deadline`` normally converts
                                # this typed boundary into a worker result.  Keep
                                # the fallback answer-free and, crucially, let
                                # the other futures in this already-admitted
                                # batch settle before stopping the next batch.
                                results[item.index] = _ValidationWorkerResult(
                                    index=item.index,
                                    raw_issue=item.raw_issue,
                                    issue_func=item.issue_func,
                                    success=False,
                                    error=exc.failure_class,
                                    evidence_pack=dict(item.evidence_pack),
                                    provider_failure_class=exc.failure_class,
                                )
                            except Exception:
                                logger.warning(
                                    "Validation worker crashed for issue %s in function %s class=%s.",
                                    item.raw_issue.get("id"),
                                    item.issue_func,
                                    "validation_worker_failure",
                                )
                                results[item.index] = _ValidationWorkerResult(
                                    index=item.index,
                                    raw_issue=item.raw_issue,
                                    issue_func=item.issue_func,
                                    success=False,
                                    error="validation_worker_failure",
                                )
                    batch_provider_failures = [
                        results[item.index]
                        for item in batch
                        if results[item.index].provider_failure_class
                    ]
                    if batch_provider_failures:
                        first_failure = min(
                            batch_provider_failures,
                            key=lambda value: int(value.index),
                        )
                        provider_failure_class = first_failure.provider_failure_class
                        state["validation_provider_failure_batch_admitted_count"] = len(batch)
                        state["validation_provider_failure_batch_settled_count"] = len(batch)
                        state["validation_provider_failure_unstarted_count"] = max(
                            0,
                            len(prepared) - batch_start - len(batch),
                        )
                        break
                    if any(
                        results[item.index].admission_failure_class == "p6_token_hard_limit"
                        for item in batch
                    ):
                        for unstarted in prepared[batch_start + len(batch) :]:
                            results[unstarted.index] = _ValidationWorkerResult(
                                index=unstarted.index,
                                raw_issue=unstarted.raw_issue,
                                issue_func=unstarted.issue_func,
                                success=False,
                                error="p6_token_hard_limit",
                                evidence_pack=dict(unstarted.evidence_pack),
                                admission_failure_class="p6_token_hard_limit",
                            )
                        break
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
                applied_result = results.get(item.index)
                if applied_result is not None:
                    self._apply_validation_worker_result(state, applied_result)
            if provider_failure_class:
                state["pending_new_issues"] = [
                    item.raw_issue
                    for item in prepared
                    if item.index not in results or results[item.index].provider_failure_class
                ]
                state["validation_queue_drained"] = False
                raise ProviderFailureError(provider_failure_class)

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
            with (
                bind_cancellation_token(token),
                llm_usage_attribution_scope(
                    stage=self._validation_usage_stage(item),
                    call_kind=self._validation_usage_call_kind(item),
                    candidate_uid=str(item.raw_issue.get("candidate_uid") or ""),
                    finding_uid=str(item.raw_issue.get("id") or ""),
                    validation_cluster_uid=str(item.raw_issue.get("validation_cluster_uid") or ""),
                ),
            ):
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
        except P6BalancedTokenAdmissionError as exc:
            # The sealed P6 ledger rejected this call before provider I/O.
            # Preserve a typed, answer-free result so the batch can collect
            # every in-flight worker and drain the queue normally.
            result = _ValidationWorkerResult(
                index=item.index,
                raw_issue=item.raw_issue,
                issue_func=item.issue_func,
                success=False,
                error=exc.failure_class,
                evidence_pack=dict(item.evidence_pack),
                admission_failure_class=exc.failure_class,
                admission_request_denied=True,
            )
        except ProviderFailureError as exc:
            # A systemic provider failure stops admission of the *next* batch,
            # not collection of siblings that were already admitted.  Store a
            # fixed class-only marker and return it to the batch collector;
            # provider bodies and exception text never enter state or logs.
            result = _ValidationWorkerResult(
                index=item.index,
                raw_issue=item.raw_issue,
                issue_func=item.issue_func,
                success=False,
                error=exc.failure_class,
                evidence_pack=dict(item.evidence_pack),
                provider_failure_class=exc.failure_class,
            )
        elapsed = max(0.0, time.monotonic() - started)
        self._record_validation_budget(item, result, soft_budget, elapsed)
        return result

    @staticmethod
    def _mark_validation_running(state: Mapping[str, Any], issue: Mapping[str, Any]) -> None:
        """Count only a Validator worker that has actually been dispatched."""

        ledger = state.get("candidate_ledger")
        mark_running = getattr(ledger, "mark_validation_running", None)
        if callable(mark_running):
            mark_running(issue)

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
    def _balanced_priority_class(item: _PreparedValidation) -> tuple[int, str, Dict[str, Any]]:
        """Rank Validator work without consulting Truth, expected, or model prose."""

        issue = item.raw_issue
        closure = issue.get("proof_kernel_closure_evaluation")
        closure = closure if isinstance(closure, Mapping) else {}
        evidence_closure = issue.get("evidence_closure_state")
        evidence_closure = evidence_closure if isinstance(evidence_closure, Mapping) else {}
        missing = [str(value) for value in closure.get("missing_clause_uids") or [] if str(value)]
        checked = [str(value) for value in closure.get("checked_clause_uids") or [] if str(value)]
        fact_missing = [
            str(value) for value in evidence_closure.get("missing_fact_kinds") or [] if str(value)
        ]
        fact_resolved = [
            str(value) for value in evidence_closure.get("resolved_fact_kinds") or [] if str(value)
        ]
        near_closure = bool(
            (checked and len(missing) <= 1) or (fact_resolved and len(fact_missing) <= 1)
        )
        proof_input = issue.get("proof_kernel_input")
        proof_input = proof_input if isinstance(proof_input, Mapping) else {}
        obligation = proof_input.get("proof_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        negative_evidence = issue.get("negative_evidence")
        high_value_counterproof = bool(
            obligation.get("counterproof_clauses")
            or (isinstance(negative_evidence, list) and negative_evidence)
            or issue.get("counterproof_plan")
            or issue.get("proof_conflict_requires_v3")
        )
        try:
            confidence = float(issue.get("confidence") or issue.get("rule_confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        low_value = bool(
            str(issue.get("candidate_disposition") or "") == "shadow_observation"
            or str(issue.get("finding_kind") or "") == "audit_only"
            or str(issue.get("audit_status") or "") == "audit_only"
            or (
                confidence < 0.35
                and not checked
                and not fact_resolved
                and not (issue.get("positive_evidence") or [])
            )
        )
        if near_closure:
            rank, label = 0, "near_closure"
        elif high_value_counterproof:
            rank, label = 1, "high_value_counterproof"
        elif low_value:
            rank, label = 3, "low_value_audit"
        else:
            rank, label = 2, "standard"
        return (
            rank,
            label,
            {
                "near_closure": near_closure,
                "high_value_counterproof": high_value_counterproof,
                "low_value": low_value,
                "truth_fields_consulted": False,
            },
        )

    def _order_balanced_validation_work(
        self,
        prepared: List[_PreparedValidation],
    ) -> List[_PreparedValidation]:
        if self._scan_depth() != "balanced" or not prepared:
            return prepared
        decorated = []
        for item in prepared:
            rank, label, basis = self._balanced_priority_class(item)
            item.raw_issue["balanced_validation_priority"] = {
                "rank": rank,
                "class": label,
                "basis": basis,
            }
            stable_uid = str(
                item.raw_issue.get("validation_cluster_uid")
                or item.raw_issue.get("candidate_uid")
                or item.raw_issue.get("id")
                or ""
            )
            decorated.append(((rank, stable_uid, int(item.index)), item))
        return [item for _key, item in sorted(decorated, key=lambda value: value[0])]

    @staticmethod
    def _balanced_scheduler_priority(item: _PreparedValidation) -> int:
        priority = item.raw_issue.get("balanced_validation_priority")
        priority = priority if isinstance(priority, Mapping) else {}
        try:
            rank = int(priority.get("rank", 2))
            risk = int(item.raw_issue.get("risk_score") or 0)
        except (TypeError, ValueError):
            rank, risk = 2, 0
        return (4 - max(0, min(3, rank))) * 1000 + max(0, min(999, risk))

    def _p6_balanced_admission_enabled(self) -> bool:
        """Return whether the current scan uses the sealed P6 admission policy."""

        ledger = getattr(self.config, "scan_token_usage_ledger", None)
        snapshot = getattr(ledger, "snapshot", None)
        if not callable(snapshot):
            return False
        try:
            ledger_snapshot = snapshot()
            admission = (
                ledger_snapshot.get("p6_balanced_admission")
                if isinstance(ledger_snapshot, Mapping)
                else None
            )
            return bool(isinstance(admission, Mapping) and admission.get("enabled") is True)
        except Exception:
            return False

    def _validation_usage_stage(self, item: _PreparedValidation) -> str:
        """Preserve the stable stage dimension for balanced scheduling."""

        priority = item.raw_issue.get("balanced_validation_priority")
        priority = priority if isinstance(priority, Mapping) else {}
        if self._p6_balanced_admission_enabled() and priority.get("class") == "low_value_audit":
            return "active_discovery"
        return "validation"

    def _validation_usage_call_kind(self, item: _PreparedValidation) -> str:
        """Mark only explicitly classified P6 low-value audit work.

        SecuritySpec and Hunter calls also use semantic/discovery stages, but
        they are not low-value merely because of that attribution.  The token
        ledger's soft watermark therefore keys exclusively on this fixed
        answer-free scheduler class.
        """

        priority = item.raw_issue.get("balanced_validation_priority")
        priority = priority if isinstance(priority, Mapping) else {}
        if (
            priority.get("class") == "low_value_audit"
            and self._validation_usage_stage(item) == "active_discovery"
        ):
            return "p6_low_value_audit"
        return ""

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
        return False

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
        logger.info(
            "Proof Engine model adapter disabled; closing %d issue(s) as review.",
            len(new_issues),
        )
        for raw_issue in new_issues:
            self._ensure_discovery_attribution(raw_issue)
            issue_func = self._issue_function(raw_issue, state)
            decision = self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
            if decision:
                raw_issue["historical_feedback_advisory"] = {
                    "action": decision.action,
                    "source": decision.rejection_source,
                    "active_product_effect": "none",
                }
            score_data = self.validation_pipeline.score_components(raw_issue, {})
            outcome = self.validation_pipeline.apply_unvalidated(raw_issue, score_data)
            raw_issue["proof_kernel_mode"] = self._PROOF_KERNEL_TERMINAL_MODE
            raw_issue.setdefault(
                "proof_kernel_decision",
                {
                    "proof_kernel_mode": self._PROOF_KERNEL_TERMINAL_MODE,
                    "disposition": "needs_review",
                    "reason_code": "proof_engine_adapter_disabled",
                    "requested_fact_kinds": [],
                    "accepted_fact_kinds": [],
                    "missing_fact_kinds": ["proof_clause"],
                    "artifact_refs": [],
                },
            )
            raw_issue["proof_kernel_terminal_authority_decision"] = (
                self._proof_kernel_terminal_decision(raw_issue)
            )
            authority = self._evaluate_bound_terminal_authority(raw_issue)
            raw_issue["terminal_authority_decision"] = authority.to_dict()
            raw_issue["terminal_authority"] = authority.authority
            raw_issue["terminal_reason_codes"] = [authority.reason_code]
            attribution = raw_issue.get("attribution")
            if isinstance(attribution, dict):
                attribution["decided_by"] = "proof_engine"
                attribution["decision_level"] = "V0"
            outcome = self._classify_final_needs_review(state, raw_issue, outcome)
            if outcome.report_bucket:
                state[outcome.report_bucket].append(raw_issue)
            if outcome.memory_status:
                self.remember_validation_result(raw_issue, outcome.memory_status)
            self._update_candidate_ledger(state, raw_issue)

    def _close_open_checker_outcome_without_model(
        self,
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
    ) -> None:
        """Close a fast-profile open clause without issuing a model call."""

        raw_issue["proof_kernel_mode"] = self._PROOF_KERNEL_TERMINAL_MODE
        raw_issue.setdefault(
            "proof_kernel_decision",
            {
                "proof_kernel_mode": self._PROOF_KERNEL_TERMINAL_MODE,
                "disposition": "needs_review",
                "reason_code": "fast_profile_open_clause",
                "requested_fact_kinds": [],
                "accepted_fact_kinds": [],
                "missing_fact_kinds": ["proof_clause"],
                "artifact_refs": [],
            },
        )
        raw_issue["proof_kernel_terminal_authority_decision"] = (
            self._proof_kernel_terminal_decision(raw_issue)
        )
        authority = self._evaluate_bound_terminal_authority(raw_issue)
        raw_issue["terminal_authority_decision"] = authority.to_dict()
        raw_issue["terminal_authority"] = authority.authority
        raw_issue["terminal_reason_codes"] = [authority.reason_code]
        raw_issue["candidate_disposition"] = "needs_review"
        raw_issue["validation_status"] = "needs_review"
        raw_issue["finding_kind"] = "needs_review"
        raw_issue["policy_disposition"] = "needs_review"
        attribution = raw_issue.get("attribution")
        if isinstance(attribution, dict):
            attribution["decided_by"] = "proof_engine"
            attribution["decision_level"] = "V0"
        state["validator_avoided_count"] = int(state.get("validator_avoided_count", 0) or 0) + 1
        outcome = self._classify_final_needs_review(
            state,
            raw_issue,
            ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict="needs_review",
                final_score=0.0,
            ),
        )
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)
        if outcome.memory_status:
            self.remember_validation_result(raw_issue, outcome.memory_status)
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
        except Exception:
            issue["fact_first_resolution"] = {
                "status": "provider_error",
                "failure_class": "deterministic_fact_provider_failed",
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
        self._record_proof_kernel_authority(
            issue,
            evidence_pack,
            tuple(value.fact_kind for value in batch.resolutions if value.fact_kind),
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
        authority = self._evaluate_bound_terminal_authority(issue)
        if authority.disposition in {"confirmed", "rejected_with_proof"}:
            return batch, self._validation_outcome_from_proof_authority(issue, authority)
        if not batch.proof_added:
            return batch, None
        return batch, None

    def _preview_fact_first_prevalidation(
        self,
        issue: Dict[str, Any],
        evidence_pack: Mapping[str, Any],
    ) -> None:
        """Record the new proof-kernel fact plan without changing V1 input.

        P2 has not qualified the new RequiredFactPlan as a product authority.
        Running it over a copy keeps the exact projected closure available for
        offline comparison while preventing shadow-only missing clauses from
        rewriting the stable candidate decision slice.
        """

        probe = deepcopy(issue)
        if not self._has_valid_security_obligation(probe):
            issue["proof_kernel_fact_first"] = {
                "status": "not_applicable",
                "reason": "missing_security_obligation",
            }
            return
        try:
            batch = self._evidence_completion_queue.resolve_required_facts(
                probe,
                validator_data={"verdict": "uncertain"},
                validation_evidence=evidence_pack,
            )
        except Exception:
            issue["proof_kernel_fact_first"] = {
                "status": "provider_error",
                "failure_class": "deterministic_fact_provider_failed",
            }
            return
        issue["proof_kernel_fact_first"] = {
            "status": str(probe.get("evidence_completion_status") or "not_applicable"),
            "evidence_delta_hash": batch.evidence_delta_hash,
            "proof_added": batch.proof_added,
            "attempted_fact_kinds": sorted(
                {value.fact_kind for value in batch.resolutions if value.fact_kind}
            ),
            "parameterized_request_scopes": [
                self._fact_first_parameterized_request_scope(
                    issue,
                    evidence_pack,
                    value.fact_kind,
                )
                for value in batch.resolutions
                if value.fact_kind
            ],
            "resolutions": [
                {
                    "fact_kind": value.fact_kind,
                    "status": value.terminal_status,
                    "provider_ids": list(value.provider_ids),
                    "miss_reason": value.miss_reason,
                }
                for value in batch.resolutions
            ],
            "decision_fact_slice": deepcopy(probe.get("decision_fact_slice") or {}),
            "evidence_closure_state": deepcopy(probe.get("evidence_closure_state") or {}),
            "candidate_promotion_eligible": probe.get("candidate_promotion_eligible"),
            "candidate_promotion_reason": probe.get("candidate_promotion_reason"),
        }
        # Keep the whole experimental fact-first path on the probe.  In
        # particular, do not let its checker contributions, closure state, or
        # promotion diagnostics leak into the live V1 decision slice.
        proof_decision = self._record_proof_kernel_authority(
            probe,
            evidence_pack,
            tuple(value.fact_kind for value in batch.resolutions if value.fact_kind),
        )
        issue["proof_kernel_fact_first"]["proof_engine"] = proof_decision

    def _record_proof_kernel_authority(
        self,
        issue: Dict[str, Any],
        evidence_pack: Mapping[str, Any],
        fact_kinds: tuple[str, ...],
    ) -> Dict[str, Any]:
        """Run the finite strict registry and freeze its authoritative closure."""

        requested = tuple(sorted({str(value) for value in fact_kinds if str(value)}))
        actions = self._function_ir_facts.actions(issue, evidence_pack, requested)
        refs = issue.setdefault("proof_kernel_artifact_refs", [])
        if not isinstance(refs, list):
            refs = []
            issue["proof_kernel_artifact_refs"] = refs
        checker_results = issue.setdefault("proof_kernel_checker_results", [])
        if not isinstance(checker_results, list):
            checker_results = []
            issue["proof_kernel_checker_results"] = checker_results
        known_checks = {
            str(value.get("check_uid") or "")
            for value in checker_results
            if isinstance(value, Mapping)
        }
        for action in actions:
            result = self._function_ir_facts.execute(action, issue, evidence_pack)
            artifacts = result.proof_artifacts or {}
            action_refs: list[str] = []
            for artifact_kind, artifact in artifacts.items():
                reference = self._decision_trace_store.put_evidence(
                    kind=artifact_kind,
                    payload=artifact,
                    producer="zscope.proof-kernel.v4",
                    dependency_hashes=tuple(
                        str(value)
                        for value in artifact.get("dependency_hashes") or []
                        if str(value)
                    ),
                )
                action_refs.append(reference)
                if reference not in refs:
                    refs.append(reference)
            checked = artifacts.get("proof_check_result")
            if isinstance(checked, Mapping):
                check_uid = str(checked.get("check_uid") or "")
                if check_uid and check_uid not in known_checks:
                    checker_results.append(dict(checked))
                    known_checks.add(check_uid)
                    check_status = str(checked.get("status") or "unknown")
                    self._trace_event(
                        issue,
                        stage="verifier",
                        actor="zscope.proof-checker",
                        reason_code={
                            "accepted": "FACT_VERIFIED_TRUE",
                            "conflicting": "FACT_CONFLICTING",
                        }.get(check_status, "FACT_UNKNOWN"),
                        output_refs=tuple(action_refs),
                        details={
                            "proof_kernel_mode": self._PROOF_KERNEL_TERMINAL_MODE,
                            "action_id": action.action_id,
                            "fact_kind": action.fact_kind,
                            "check_uid": check_uid,
                            "check_status": check_status,
                            "terminal_contribution": str(
                                checked.get("terminal_contribution") or "none"
                            ),
                        },
                        dedupe_key=f"proof-check:{check_uid}",
                    )
        accepted = {
            str((value.get("accepted_fact") or {}).get("fact_kind") or "")
            for value in checker_results
            if isinstance(value, Mapping)
            and value.get("status") == "accepted"
            and isinstance(value.get("accepted_fact"), Mapping)
        }
        missing = sorted(set(requested) - accepted)
        contributions = {
            str(value.get("terminal_contribution") or "")
            for value in checker_results
            if isinstance(value, Mapping) and value.get("status") == "accepted"
        }
        if "confirmation" in contributions and "counterproof" in contributions:
            proof_disposition = "needs_review"
            proof_reason = "programmatic_proof_conflict"
        elif "counterproof" in contributions:
            proof_disposition = "rejected_with_proof"
            proof_reason = "verified_counterproof"
        elif requested and not missing and "confirmation" in contributions:
            proof_disposition = "confirmed"
            proof_reason = "verified_confirmation_proof"
        else:
            proof_disposition = "needs_review"
            proof_reason = "open_or_unknown_proof_clause"
        checker_refs = [
            "sha256:" + content_sha256(value)
            for value in checker_results
            if isinstance(value, Mapping)
        ]
        root_manifest_sha256 = content_sha256(
            {
                "schema_version": "zscope.proof-root-manifest.v1",
                "artifact_refs": sorted(set(map(str, refs))),
                "checker_result_refs": sorted(set(checker_refs)),
            }
        )
        decision = {
            "proof_kernel_mode": self._PROOF_KERNEL_TERMINAL_MODE,
            "disposition": proof_disposition,
            "reason_code": proof_reason,
            "requested_fact_kinds": list(requested),
            "accepted_fact_kinds": sorted(accepted & set(requested)),
            "missing_fact_kinds": missing,
            "artifact_refs": list(refs),
            "checker_result_refs": checker_refs,
            "root_manifest_sha256": root_manifest_sha256,
        }
        issue["proof_kernel_reverification_status"] = "verified"
        issue["proof_kernel_checker_result_refs"] = checker_refs
        issue["proof_kernel_root_manifest_sha256"] = root_manifest_sha256
        issue["proof_kernel_mode"] = self._PROOF_KERNEL_TERMINAL_MODE
        issue["proof_kernel_decision"] = decision
        issue["proof_kernel_terminal_authority_decision"] = self._proof_kernel_terminal_decision(
            issue
        )
        return decision

    def _reverify_attached_proof_kernel_input(self, issue: Dict[str, Any]) -> None:
        """Recompute one already producer-verified proof input.

        This method validates reducer syntax and semantics only.  Live entry
        points must first reconstruct the input through
        :meth:`_rebuild_live_proof_input`; an attached mapping is never a
        producer receipt merely because it has the authority-input shape.
        """

        raw = issue.get("proof_kernel_input")
        if raw is None:
            return
        if (
            not isinstance(raw, Mapping)
            or set(raw)
            != {
                "schema_version",
                "proof_ir",
                "proof_obligation",
                "selected_action_uids",
            }
            or raw.get("schema_version") != PROOF_KERNEL_AUTHORITY_INPUT_VERSION
        ):
            self._clear_v4_proof_projection(issue)
            issue["proof_kernel_decision"] = {
                "proof_kernel_mode": self._PROOF_KERNEL_TERMINAL_MODE,
                "disposition": "needs_review",
                "reason_code": "proof_kernel_input_schema_invalid",
                "requested_fact_kinds": [],
                "accepted_fact_kinds": [],
                "missing_fact_kinds": ["proof_kernel_input"],
                "artifact_refs": [],
            }
            issue["proof_kernel_reverification_status"] = "failed"
            return
        # A prior attempt may have left a byte-valid certificate and terminal
        # projection for another selection.  Preserve only the reconstructed
        # producer input and recompute every reducer-owned object below.
        self._clear_v4_proof_projection(issue, clear_input=False)
        try:
            selected_action_uids = tuple(map(str, raw["selected_action_uids"]))
            engine = ProofKernelEngine()
            evaluation = (
                engine.evaluate_selected_actions(
                    proof_ir=raw["proof_ir"],
                    obligation=raw["proof_obligation"],
                    selected_action_uids=selected_action_uids,
                )
                if selected_action_uids
                else engine.evaluate(
                    proof_ir=raw["proof_ir"],
                    obligation=raw["proof_obligation"],
                )
            )
            self._record_v4_proof_evaluation(
                issue,
                evaluation,
                selected_action_uids=selected_action_uids,
            )
        except (KeyError, TypeError, ValueError):
            self._clear_v4_proof_projection(issue)
            issue["proof_kernel_decision"] = {
                "proof_kernel_mode": self._PROOF_KERNEL_TERMINAL_MODE,
                "disposition": "needs_review",
                "reason_code": "proof_kernel_reverification_failed",
                "requested_fact_kinds": [],
                "accepted_fact_kinds": [],
                "missing_fact_kinds": ["proof_kernel_reverification"],
                "artifact_refs": [],
                "failure_class": "proof_kernel_reverification_failed",
            }
            issue["proof_kernel_reverification_status"] = "failed"

    @staticmethod
    def _reset_live_candidate_projection(issue: Dict[str, Any]) -> None:
        """Return a persisted candidate to an unresolved live-entry state."""

        issue["candidate_disposition"] = "needs_review"
        issue["validation_status"] = "needs_review"
        issue["policy_disposition"] = "needs_review"
        issue["finding_kind"] = "needs_review"
        issue.pop("model_verdict", None)
        issue.pop("confirmed", None)
        issue.pop("is_confirmed", None)
        issue.pop("verdict", None)
        issue.pop("terminal_disposition", None)
        issue.pop("status", None)
        issue.pop("validator_policy_outcome", None)
        issue.pop("audit_eligibility", None)
        issue.pop("audit_status", None)
        issue.pop("audit_reason_codes", None)
        issue.pop("candidate_terminal_authority_failure_class", None)
        attribution = issue.get("attribution")
        if isinstance(attribution, dict):
            attribution["decided_by"] = "unresolved"
            attribution["decision_level"] = "none"
            attribution["decision_details"] = {}

    def _attach_hunter_proof_input(self, issue: Dict[str, Any]) -> bool:
        """Reconstruct one Hunter proof solely from its current sealed offer."""

        from ...orchestration.hypothesis_hunter.models import (
            validate_hypothesis_offer,
            validate_security_hypothesis,
        )

        offer = issue.get("hypothesis_offer")
        hypothesis = issue.get("security_hypothesis")
        if not isinstance(offer, Mapping) or not isinstance(hypothesis, Mapping):
            issue["proof_kernel_input_rebuild_status"] = "hunter_producer_objects_missing"
            return False
        offer_valid, _ = validate_hypothesis_offer(offer)
        hypothesis_valid, _ = validate_security_hypothesis(hypothesis, offer=offer)
        if not offer_valid or not hypothesis_valid:
            issue["proof_kernel_input_rebuild_status"] = "hunter_producer_binding_invalid"
            return False
        proof_ir = offer.get("proof_ir")
        obligation = offer.get("proof_obligation")
        selected = hypothesis.get("evidence_action_uids")
        if (
            not isinstance(proof_ir, Mapping)
            or not isinstance(obligation, Mapping)
            or not isinstance(selected, list)
        ):
            issue["proof_kernel_input_rebuild_status"] = "hunter_proof_input_invalid"
            return False
        selected_action_uids = tuple(map(str, selected))
        issue["proof_kernel_input"] = {
            "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
            "proof_ir": deepcopy(dict(proof_ir)),
            "proof_obligation": deepcopy(dict(obligation)),
            "selected_action_uids": list(selected_action_uids),
        }
        issue["proof_kernel_input_origin"] = "hypothesis_hunter_offer_v4"
        issue["proof_kernel_input_rebuild_status"] = "frozen"
        producer_binding, occurrence_binding = revalidate_v4_producer_occurrence_binding(issue)
        if not producer_binding or not occurrence_binding:
            self._clear_v4_proof_projection(issue)
            issue["proof_kernel_input_rebuild_status"] = "hunter_producer_binding_invalid"
            return False
        self._reverify_attached_proof_kernel_input(issue)
        verified = issue.get("proof_kernel_reverification_status") == "verified"
        if verified:
            issue["proof_kernel_producer_binding_sha256"] = producer_binding
            issue["proof_kernel_occurrence_binding_sha256"] = occurrence_binding
        return verified

    def _attach_product_composite_proof_input(
        self,
        issue: Dict[str, Any],
        evidence_pack: Mapping[str, Any],
    ) -> bool:
        """Freeze the ordinary Validator candidate's complete v4 obligation.

        Ordinary candidates are composed only after the evidence pack is
        available, using the independently rebuilt CandidateEnvelope,
        governed SecurityObligation identity and FunctionIR action catalog.
        """

        # Candidates produced before the governed SecurityObligation cutover
        # remain readable, but must not acquire a newly inferred product proof
        # shape during compatibility replay.
        if issue.get("security_obligation_v1") is not True:
            issue["proof_kernel_composite_status"] = "legacy_candidate_without_frozen_contract"
            return False
        composite = self._function_ir_facts.build_composite_proof_input(
            issue,
            evidence_pack,
        )
        if composite is None:
            issue["proof_kernel_composite_status"] = "not_constructible"
            return False
        issue["proof_kernel_input"] = composite
        issue["proof_kernel_input_origin"] = "product_composite_obligation_v4"
        issue["proof_kernel_composite_family"] = self._function_ir_facts.composite_family(issue)
        issue["proof_kernel_composite_status"] = "frozen"
        issue["proof_kernel_input_rebuild_status"] = "frozen"
        proof_ir = composite.get("proof_ir")
        obligation = composite.get("proof_obligation")
        selected = composite.get("selected_action_uids")
        if (
            not isinstance(proof_ir, Mapping)
            or not isinstance(obligation, Mapping)
            or not isinstance(selected, list)
        ):
            self._clear_v4_proof_projection(issue)
            issue["proof_kernel_composite_status"] = "producer_binding_invalid"
            return False
        producer_binding, occurrence_binding = revalidate_v4_producer_occurrence_binding(issue)
        if not producer_binding or not occurrence_binding:
            self._clear_v4_proof_projection(issue)
            issue["proof_kernel_composite_status"] = "producer_binding_invalid"
            return False
        self._reverify_attached_proof_kernel_input(issue)
        verified = issue.get("proof_kernel_reverification_status") == "verified"
        if verified:
            issue["proof_kernel_producer_binding_sha256"] = producer_binding
            issue["proof_kernel_occurrence_binding_sha256"] = occurrence_binding
        return verified

    def _rebuild_live_proof_input(
        self,
        issue: Dict[str, Any],
        evidence_pack: Mapping[str, Any],
    ) -> bool:
        """Discard persisted proof projections and reconstruct current authority."""

        source = str(issue.get("candidate_source") or issue.get("origin") or "").lower()
        self._clear_v4_proof_projection(issue)
        self._reset_live_candidate_projection(issue)
        if source == "hypothesis_hunter":
            rebuilt = self._attach_hunter_proof_input(issue)
        elif issue.get("security_obligation_v1") is True:
            rebuilt = self._attach_product_composite_proof_input(issue, evidence_pack)
        else:
            issue["proof_kernel_input_rebuild_status"] = "legacy_or_unknown_candidate"
            rebuilt = False
        if not rebuilt:
            # Builder failures must not retain a partially reconstructed input
            # or any certificate/authority projection from the failed attempt.
            status = str(
                issue.get("proof_kernel_input_rebuild_status")
                or issue.get("proof_kernel_composite_status")
                or "producer_binding_invalid"
            )
            self._clear_v4_proof_projection(issue)
            self._reset_live_candidate_projection(issue)
            issue["proof_kernel_input_rebuild_status"] = status
        return rebuilt

    @staticmethod
    def _clear_v4_proof_projection(
        issue: Dict[str, Any],
        *,
        clear_input: bool = True,
    ) -> None:
        """Remove every mutable projection that could carry old v4 authority."""

        for key in (
            "proof_kernel_evaluation",
            "proof_kernel_fact_first",
            "proof_kernel_frozen_state",
            "proof_kernel_closure_evaluation",
            "proof_kernel_promotion_certificate",
            "proof_kernel_terminal_authority_decision",
            "terminal_authority_decision",
            "terminal_authority",
            "terminal_reason_codes",
            "proof_kernel_checker_results",
            "proof_kernel_checker_result_refs",
            "proof_kernel_artifact_refs",
            "proof_kernel_root_manifest_sha256",
            "proof_kernel_decision",
            "proof_kernel_live_selected_action_uids",
            "proof_kernel_reverification_status",
            "proof_kernel_v2_reentry_status",
            "proof_kernel_v3_reentry_status",
            "proof_kernel_producer_binding_sha256",
            "proof_kernel_occurrence_binding_sha256",
            "candidate_promotion_eligible",
            "candidate_promotion_reason",
            "candidate_promotion_terminal_status",
            "deterministic_prevalidation_decision",
            "terminal_transition_level",
            "terminal_transition_disposition",
            "terminal_transition_event_uid",
            "terminal_transition_event_hash",
            "terminal_transition_authority_sha256",
            "terminal_event_uid",
        ):
            issue.pop(key, None)
        if clear_input:
            for key in (
                "proof_kernel_input",
                "proof_kernel_input_origin",
                "proof_kernel_composite_family",
                "proof_kernel_composite_status",
                "proof_kernel_input_rebuild_status",
            ):
                issue.pop(key, None)

    def _record_v4_proof_evaluation(
        self,
        issue: Dict[str, Any],
        evaluation: Any,
        *,
        selected_action_uids: tuple[str, ...],
    ) -> None:
        """Persist one reducer result without inventing a second obligation.

        The v4 objects are the live authority; no compatibility projection may
        acquire a parallel meaning or become an accidental promotion input.
        """

        frozen = evaluation.frozen_state.to_dict()
        closure = evaluation.closure_evaluation.to_dict()
        evaluation.apply_to_issue(issue)
        issue["proof_kernel_mode"] = evaluation.proof_kernel_mode
        issue["proof_kernel_checker_results"] = [dict(value) for value in evaluation.check_results]
        issue["proof_kernel_artifact_refs"] = list(evaluation.artifact_refs)
        issue["proof_kernel_checker_result_refs"] = list(evaluation.checker_result_refs)
        issue["proof_kernel_root_manifest_sha256"] = evaluation.root_manifest_sha256
        raw = issue.get("proof_kernel_input")
        raw = raw if isinstance(raw, Mapping) else {}
        try:
            catalog = ProofKernelEngine().action_catalog(
                proof_ir=raw["proof_ir"],
                obligation=raw["proof_obligation"],
            )
        except (KeyError, TypeError, ValueError):
            catalog = ()
        issue["proof_kernel_decision"] = {
            "schema_version": evaluation.schema_version,
            "proof_kernel_mode": evaluation.proof_kernel_mode,
            "disposition": evaluation.decision,
            "reason_code": evaluation.reason_code,
            "requested_fact_kinds": sorted(
                {
                    str(value.get("fact_kind") or "")
                    for value in catalog
                    if str(value.get("fact_kind") or "")
                }
            ),
            "accepted_fact_kinds": sorted(
                {
                    str((value.get("accepted_fact") or {}).get("fact_kind") or "")
                    for value in evaluation.check_results
                    if value.get("status") == "accepted"
                    and isinstance(value.get("accepted_fact"), Mapping)
                }
            ),
            "missing_fact_kinds": list(closure.get("missing_clause_uids") or []),
            "artifact_refs": list(evaluation.artifact_refs),
            "checker_result_refs": list(evaluation.checker_result_refs),
            "root_manifest_sha256": evaluation.root_manifest_sha256,
        }
        issue["proof_kernel_live_selected_action_uids"] = list(
            dict.fromkeys(map(str, selected_action_uids))
        )
        issue["proof_kernel_reverification_status"] = "verified"
        authority = self._terminal_authority.evaluate(
            issue,
            operation="live",
        )
        issue["proof_kernel_terminal_authority_decision"] = authority.to_dict()
        issue["terminal_authority_decision"] = authority.to_dict()

    def _evaluate_bound_terminal_authority(
        self,
        issue: Mapping[str, Any],
        *,
        model_result: Optional[Mapping[str, Any]] = None,
        has_executable_action: bool = False,
        protocol_or_engine_failure: bool = False,
        operation: AuthorityOperation = "live",
    ) -> TerminalAuthorityDecision:
        """Evaluate live authority only after producer/occurrence rebuilding.

        The reducer can prove only that its own supplied objects are mutually
        consistent.  A mismatched or absent producer/occurrence receipt must
        therefore be removed from the evaluator's input domain rather than
        passed alongside a failure flag (a valid self-sealed promotion would
        otherwise still be returned before that flag is considered).
        """

        if not has_exact_v4_producer_occurrence_binding(issue):
            if not protocol_or_engine_failure:
                unbound = self._terminal_authority.evaluate(
                    issue,
                    model_result=model_result,
                    has_executable_action=has_executable_action,
                    operation=operation,
                )
                if unbound.disposition == "needs_review":
                    return unbound
            return self._terminal_authority.evaluate(
                {},
                model_result=model_result,
                has_executable_action=has_executable_action,
                protocol_or_engine_failure=True,
                operation=operation,
            )
        return self._terminal_authority.evaluate(
            issue,
            model_result=model_result,
            has_executable_action=has_executable_action,
            protocol_or_engine_failure=protocol_or_engine_failure,
            operation=operation,
        )

    def _matching_frozen_proof_action_uid(
        self,
        issue: Mapping[str, Any],
        action: EvidenceAction,
        evidence_pack: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """Map a V3 fact action to exactly one action in the original catalog."""

        raw = issue.get("proof_kernel_input")
        if not isinstance(raw, Mapping):
            return ""
        try:
            catalog = ProofKernelEngine().action_catalog(
                proof_ir=raw["proof_ir"],
                obligation=raw["proof_obligation"],
            )
        except (KeyError, TypeError, ValueError):
            return ""
        proof_parameters = self._function_ir_facts.proof_parameters_for_action(
            action,
            issue,
            evidence_pack,
        )
        if proof_parameters is None:
            return ""
        matches = [
            value
            for value in catalog
            if str(value.get("fact_kind") or "") == action.fact_kind
            and str(value.get("subject_uid") or "") == action.subject_uid
            and str(value.get("decision_region_uid") or "") == action.decision_region_uid
            and dict(value.get("fixed_parameters") or {}) == proof_parameters
        ]
        if len(matches) != 1:
            return ""
        return str(matches[0].get("action_uid") or "")

    def _matching_frozen_v2_action_uid(
        self,
        issue: Mapping[str, Any],
        *,
        request_identity: Mapping[str, Any],
        evidence_delta: Mapping[str, Any],
    ) -> str:
        """Map one conclusive V2 fact back to the original v4 catalog.

        Fact completion may refine a decision slice, but it must not create a
        parallel proof obligation.  Re-entry is therefore allowed only when a
        replayable fact closes the requested kind and the exact
        kind/subject/function/fixed-parameter scope selects one catalog action
        from the already frozen obligation.
        """

        raw = issue.get("proof_kernel_input")
        if not isinstance(raw, Mapping):
            return ""
        fact_kind = str(request_identity.get("fact_kind") or "")
        subject_uid = str(request_identity.get("subject_uid") or "")
        function_uid = str(request_identity.get("function_uid") or "")
        issue_function = str(
            issue.get("function_signature")
            or issue.get("function")
            or issue.get("function_name")
            or ""
        )
        if not fact_kind or not subject_uid or (function_uid and function_uid != issue_function):
            return ""
        facts = [value for value in evidence_delta.get("facts") or [] if isinstance(value, Mapping)]
        if not any(
            value.get("certificate_authoritative") is True
            and fact_kind
            in {str(kind) for kind in value.get("satisfies_fact_kinds") or [] if str(kind)}
            for value in facts
        ):
            return ""
        try:
            catalog = ProofKernelEngine().action_catalog(
                proof_ir=raw["proof_ir"],
                obligation=raw["proof_obligation"],
            )
        except (KeyError, TypeError, ValueError):
            return ""
        requested_parameters = request_identity.get("fixed_parameters")
        allowed_parameters: tuple[dict[str, Any], ...]
        if isinstance(requested_parameters, Mapping):
            allowed_parameters = (dict(requested_parameters),)
        elif isinstance(requested_parameters, list) and all(
            isinstance(value, Mapping) for value in requested_parameters
        ):
            allowed_parameters = tuple(dict(value) for value in requested_parameters)
        else:
            return ""
        matches = [
            value
            for value in catalog
            if str(value.get("fact_kind") or "") == fact_kind
            and str(value.get("subject_uid") or "") == subject_uid
            and dict(value.get("fixed_parameters") or {}) in allowed_parameters
        ]
        if len(matches) != 1:
            return ""
        return str(matches[0].get("action_uid") or "")

    def _reenter_frozen_proof_obligation(
        self,
        issue: Dict[str, Any],
        *,
        action_uid: str,
    ) -> bool:
        """Re-evaluate the original v4 obligation after one accepted V3 fact."""

        raw = issue.get("proof_kernel_input")
        if not isinstance(raw, Mapping) or not action_uid:
            issue["proof_kernel_v3_reentry_status"] = "missing_frozen_obligation_action"
            return False
        initial = raw.get("selected_action_uids")
        if not isinstance(initial, (list, tuple)):
            issue["proof_kernel_v3_reentry_status"] = "invalid_frozen_obligation_selection"
            return False
        prior = issue.get("proof_kernel_live_selected_action_uids")
        prior = prior if isinstance(prior, list) else list(initial)
        selected = tuple(dict.fromkeys([*map(str, prior), str(action_uid)]))
        try:
            evaluation = ProofKernelEngine().evaluate_selected_actions(
                proof_ir=raw["proof_ir"],
                obligation=raw["proof_obligation"],
                selected_action_uids=selected,
            )
        except (KeyError, TypeError, ValueError):
            issue["proof_kernel_v3_reentry_status"] = "proof_kernel_reentry_failed"
            return False
        self._record_v4_proof_evaluation(
            issue,
            evaluation,
            selected_action_uids=selected,
        )
        issue["proof_kernel_v3_reentry_status"] = "reduced_original_obligation"
        return True

    def _prepare_issue_for_validation(
        self,
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        index: int,
    ) -> Optional[_PreparedValidation]:
        self._ensure_discovery_attribution(raw_issue)
        issue_func = self._issue_function(raw_issue, state)
        logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)

        decision = self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
        if decision:
            logger.info(
                "Issue %s has historical feedback from %s (%s); P5 keeps it non-terminal.",
                raw_issue.get("id"),
                decision.rejection_source,
                decision.action,
            )
            raw_issue["historical_feedback_advisory"] = {
                "action": decision.action,
                "source": decision.rejection_source,
                "active_product_effect": "none",
            }

        issue_code = self._issue_code(issue_func, state)
        evidence_pack = self._build_evidence_pack(raw_issue, state, issue_code)
        self._rebuild_live_proof_input(raw_issue, evidence_pack)
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
        raw_issue["proof_kernel_mode"] = self._PROOF_KERNEL_TERMINAL_MODE
        attached_authority = self._evaluate_bound_terminal_authority(raw_issue)
        if attached_authority.disposition in {"confirmed", "rejected_with_proof"}:
            self._trace_event(
                raw_issue,
                stage="V0",
                actor="proof_kernel",
                reason_code=(
                    "NEGATIVE_PROOF_COMPLETE"
                    if attached_authority.disposition == "rejected_with_proof"
                    else "POSITIVE_PROOF_COMPLETE"
                ),
                output_refs=(evidence_ref,),
                dedupe_key=f"v0-proof:{self._trace_cluster_uid(raw_issue)}",
                required=True,
            )
            self._mark_terminal_transition(raw_issue, "V0", attached_authority)
            attached_outcome = self._validation_outcome_from_proof_authority(
                raw_issue, attached_authority
            )
            self._record_deterministic_prevalidation_outcome(state, raw_issue, attached_outcome)
            if attached_outcome.report_bucket:
                state[attached_outcome.report_bucket].append(raw_issue)
            if attached_outcome.memory_status:
                self.remember_validation_result(raw_issue, attached_outcome.memory_status)
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
        # Fact-first remains a shadow comparison until its protocol is
        # independently qualified.  It may inspect a deep copy, but cannot
        # rewrite the live decision facts, close a candidate, or change the V1
        # input.  Stable attached V0 proofs above remain authoritative.
        self._preview_fact_first_prevalidation(raw_issue, evidence_pack)

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
                "schema_version": "zscope.finding-attribution.v2",
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
        if any("hypothesis_hunter" in value for value in sources):
            discovered.add("hypothesis_hunter")
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
                validator_agent = validator_agent or self._build_proof_engine_agent()
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
            validator_input = self._validator_input(
                item.raw_issue, item.issue_code, item.evidence_pack
            )
            cached = self._validator_cache_get(cache_key, validator_input=validator_input)
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
                    cached_value = self._validator_result_cache.wait(
                        cache_key,
                        timeout=self._validation_cache_wait_seconds(),
                    )
                    cached = self._validated_cached_result(
                        cached_value, validator_input=validator_input
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
                    if cached_value is not None:
                        self._validator_result_cache.discard(cache_key)
                    cache_owner = self._validator_result_cache.reserve(cache_key)
            validator_agent = validator_agent or self._build_proof_engine_agent()
            token_metadata = self._empty_token_metadata()
            usage_start = len(self._cluster_usage_events(item.raw_issue))
            val_resp = validator_agent.run(validator_input)
            self._merge_response_metadata(token_metadata, getattr(val_resp, "metadata", {}) or {})

            if not val_resp.success:
                recoverable_failure_class = self._recoverable_v1_failure_class(val_resp)
                if not item.allow_v3 or not recoverable_failure_class:
                    self._record_model_trace(
                        item.raw_issue,
                        stage="V1",
                        structured_input=validator_input,
                        structured_output={
                            "protocol_failure": True,
                            "failure_class": "validator_v1_unrecoverable_failure",
                            "failure_count": 1,
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
                    if recoverable_failure_class == "validator_v1_output_truncated"
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
                item.raw_issue["validator_v1_recoverable_failure_class"] = recoverable_failure_class
                item.raw_issue["validator_v1_recoverable_failure_count"] = 1
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
            proof_authority = self._evaluate_bound_terminal_authority(item.raw_issue)
            if proof_authority.disposition not in {
                "confirmed",
                "rejected_with_proof",
            }:
                val_data = self._run_v3_targeted_investigation(
                    item,
                    validator_agent,
                    val_data,
                    token_metadata,
                )
            if self._validator_cache_put(cache_key, val_data, validator_input=validator_input):
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
        return bool(ValidationRunner._recoverable_v1_failure_class(response))

    @staticmethod
    def _recoverable_v1_failure_class(response: Any) -> str:
        metadata = getattr(response, "metadata", {}) or {}
        finish_reason = str(metadata.get("finish_reason") or "").strip().lower()
        if finish_reason == "length" or metadata.get("snapshot_terminal_tool_failed"):
            return "validator_v1_output_truncated"
        if metadata.get("validator_protocol_exhausted"):
            return "validator_v1_malformed_output"
        error = str(getattr(response, "error", "") or "").lower()
        if "truncat" in error:
            return "validator_v1_output_truncated"
        if any(token in error for token in ("malformed", "parse", "schema", "json")):
            return "validator_v1_malformed_output"
        return ""

    def _validator_cache_get(
        self,
        cache_key: str,
        *,
        validator_input: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        cached = self._validator_result_cache.get(cache_key)
        if cached is not None:
            validated = self._validated_cached_result(cached, validator_input=validator_input)
            if validated is not None:
                return validated
            self._validator_result_cache.discard(cache_key)
        loader = getattr(self.snapshot_store, "load_validation_result", None)
        if not self._validation_persistent_cache_enabled or not callable(loader) or not cache_key:
            return None
        try:
            cached = loader(
                cache_key,
                protocol=self._validation_cache_protocol,
                candidate_schema_version=CANDIDATE_SCHEMA_VERSION,
                environment_fingerprint=self._validation_environment_fingerprint,
            )
        except Exception:
            logger.error("class=validation_cache_read_failed; count=1")
            return None
        validated = self._validated_cached_result(cached, validator_input=validator_input)
        if validated is not None:
            self._validator_result_cache.put(cache_key, validated)
            return validated
        return None

    def _validator_cache_put(
        self,
        cache_key: str,
        val_data: Dict[str, Any],
        *,
        validator_input: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        validated = self._validated_cached_result(val_data, validator_input=validator_input)
        if not cache_key or validated is None or not self._validator_result_is_cacheable(validated):
            return False
        self._validator_result_cache.put(cache_key, validated)
        saver = getattr(self.snapshot_store, "save_validation_result", None)
        if not self._validation_persistent_cache_enabled or not callable(saver):
            return True
        try:
            saver(
                cache_key,
                validated,
                protocol=self._validation_cache_protocol,
                candidate_schema_version=CANDIDATE_SCHEMA_VERSION,
                environment_fingerprint=self._validation_environment_fingerprint,
                max_entries=max(1, self._validator_result_cache_size * 2),
            )
        except Exception:
            logger.error("class=validation_cache_write_failed; count=1")
        return True

    @classmethod
    def _validator_result_is_cacheable(cls, val_data: Dict[str, Any]) -> bool:
        parsed = parse_validator_result_v3(val_data)
        if parsed is None:
            return False
        # A V3 terminal is authoritative only together with the cited
        # tool-backed fact records attached to the issue.  The legacy result
        # cache stores only ValidatorResult, so caching it would drop the
        # promotion evidence on replay.
        if parsed.validation_pass == "investigation_synthesis":
            return False
        stop_reason = parsed.stop_reason.strip().lower()
        return stop_reason not in cls._TRANSIENT_VALIDATOR_STOP_REASONS

    @staticmethod
    def _validated_cached_result(
        value: Any,
        *,
        validator_input: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(value, Mapping):
            return None
        candidate_uid = ""
        cluster_uid = ""
        expected_pass = ""
        allowed_refs: Optional[List[str]] = None
        if validator_input is not None:
            evidence_slice = validator_input.get("evidence_slice")
            if not isinstance(evidence_slice, Mapping):
                return None
            obligation = evidence_slice.get("obligation")
            obligation = obligation if isinstance(obligation, Mapping) else {}
            candidate_uid = str(
                validator_input.get("finding_uid") or obligation.get("candidate_uid") or ""
            )
            cluster_uid = str(
                validator_input.get("validation_cluster_uid")
                or obligation.get("validation_cluster_uid")
                or ""
            )
            expected_pass = str(validator_input.get("validation_pass") or "initial")
            catalog = evidence_slice.get("evidence_ref_catalog")
            if not isinstance(catalog, Mapping):
                return None
            allowed_refs = sorted(str(value) for value in catalog if str(value))
            if not candidate_uid or not cluster_uid:
                return None
        parsed = parse_validator_result_v3(
            value,
            candidate_uid=candidate_uid,
            validation_cluster_uid=cluster_uid,
            expected_pass=expected_pass,
            allowed_evidence_refs=allowed_refs,
        )
        return parsed.to_dict() if parsed is not None else None

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
                "protocol": self._validation_cache_protocol,
                "decision_context_version": DECISION_CONTEXT_VERSION,
                "environment": self._validation_environment_fingerprint,
                "rendered_prompt_contract_sha256": self._validation_prompt_contract_sha256,
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
            "protocol": self._validation_cache_protocol,
            "decision_context_version": DECISION_CONTEXT_VERSION,
            "environment": self._validation_environment_fingerprint,
            "rendered_prompt_contract_sha256": self._validation_prompt_contract_sha256,
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
                if getattr(agent, "name", "") == "proof_engine"
            ),
            None,
        )
        profiles = getattr(getattr(self.config, "scan", None), "llm_profiles", None)
        llm_ref = str(getattr(profiles, "validation", "") or "")
        if not llm_ref:
            llm_ref = str(getattr(validator_cfg, "llm_ref", "") or "default")
        client = self.llm_clients.get(llm_ref) or self.llm_clients.get("default")
        prompt_contract_sha256 = getattr(self, "_validation_prompt_contract_sha256", "")
        if not prompt_contract_sha256:
            prompt_contract = self._build_validation_prompt_contract()
            prompt_contract_sha256 = self._stable_hash(prompt_contract)
        payload = {
            "protocol": self._validation_cache_protocol,
            "decision_context_version": DECISION_CONTEXT_VERSION,
            "project_root": project_root.resolve().as_posix(),
            "project_revision": self._project_revision(project_root),
            "index_epoch": self._index_epoch(),
            "validator_llm_ref": llm_ref,
            "llm_client": self._llm_identity(client),
            "validator_contract": getattr(validator_cfg, "contract", None),
            "validator_prompt_version": getattr(validator_cfg, "prompt_version", None),
            # Bind the content that is actually rendered for the Proof Engine,
            # not merely a caller-maintained prompt-version label.  This also
            # covers a project-local ``.zscope/agents/proof_engine/AGENT.md``
            # override because ``attach_agent_contract`` has already resolved
            # the effective project SpecRegistry entry.
            "rendered_prompt_contract_sha256": prompt_contract_sha256,
            "tool_policy": self._tool_policy_identity(),
            "effective_rules_sha256": self._effective_rules_sha256(),
        }
        return self._stable_hash(payload)

    def _build_validation_prompt_contract(self) -> Dict[str, Any]:
        """Freeze the effective Proof Engine prompt/schema contract.

        A prompt-version string is not a content binding: an AGENT.md edit, a
        project override, or a strict response-schema edit could otherwise
        reuse a result produced under a different model contract.  Render the
        exact system-contract sections used by ``ToolCallingAgent`` and one
        canonical v3 user prompt, and bind the provider-facing schema/delivery
        mode.  Per-call traces add the frozen evidence slice below.
        """

        context: Dict[str, Any] = {}
        try:
            self.attach_agent_contract(context, "proof_engine")
            binding_status = "bound"
        except Exception:
            # Runtime invocation will fail closed at the same contract
            # boundary.  Keep fingerprint construction answer-free and avoid
            # serializing exception bodies into cache or trace identities.
            context = {}
            binding_status = "binding_failure"
        profiles = getattr(getattr(self.config, "scan", None), "llm_profiles", None)
        llm_ref = str(getattr(profiles, "validation", "") or "")
        if not llm_ref:
            validator_cfg = next(
                (
                    agent
                    for agent in (
                        getattr(getattr(self.config, "project", None), "agents", None) or []
                    )
                    if getattr(agent, "name", "") == "proof_engine"
                ),
                None,
            )
            llm_ref = str(getattr(validator_cfg, "llm_ref", "") or "default")
        client = self.llm_clients.get(llm_ref) or self.llm_clients.get("default")
        return {
            "binding_status": binding_status,
            "system_prompt": self._compose_validation_system_prompt(context),
            "user_prompt": ProofEngineAgent._validator_v3_prompt({}, "initial"),
            "response_schema": validator_result_schema_v3(),
            "schema_delivery": (
                "strict_json_schema"
                if bool(getattr(client, "supports_structured_output", False))
                else "terminal_tool"
            ),
            "terminal_tool_name": "emit_validator_result_v3",
        }

    @staticmethod
    def _compose_validation_system_prompt(context: Mapping[str, Any]) -> str:
        """Mirror ``ToolCallingAgent._compose_system_prompt`` exactly."""

        system_prompt = str(context.get("agent_contract") or "")
        workflow_context = context.get("workflow_context")
        if workflow_context:
            system_prompt += f"\n\n[Workflow Contract]\n{workflow_context}"
        skill_contracts = context.get("skill_contracts")
        if skill_contracts:
            system_prompt += f"\n\n[Loaded Skill Contracts]\n{skill_contracts}"
        return system_prompt

    def _rendered_validation_prompt_schema_sha256(
        self,
        structured_input: Mapping[str, Any],
    ) -> str:
        """Hash the exact v3 prompt/schema rendered for one model event."""

        evidence_slice = structured_input.get("evidence_slice")
        if not isinstance(evidence_slice, dict):
            return self._validation_prompt_contract_sha256
        validation_pass = str(structured_input.get("validation_pass") or "initial")
        obligation = evidence_slice.get("obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        candidate_uid = str(
            structured_input.get("finding_uid") or obligation.get("candidate_uid") or ""
        )
        cluster_uid = str(
            structured_input.get("validation_cluster_uid")
            or obligation.get("validation_cluster_uid")
            or ""
        )
        catalog = evidence_slice.get("evidence_ref_catalog")
        allowed_refs = sorted(str(value) for value in catalog) if isinstance(catalog, dict) else []
        return self._stable_hash(
            {
                "system_prompt": self._compose_validation_system_prompt(structured_input),
                "user_prompt": ProofEngineAgent._validator_v3_prompt(
                    evidence_slice,
                    validation_pass,
                ),
                "response_schema": validator_result_schema_v3(
                    candidate_uid=candidate_uid,
                    validation_cluster_uid=cluster_uid,
                    expected_pass=validation_pass,
                    allowed_evidence_refs=allowed_refs,
                ),
                "schema_delivery": self._validation_prompt_contract.get("schema_delivery"),
                "terminal_tool_name": "emit_validator_result_v3",
            }
        )

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
            policy = self.tool_policy_for_agent("proof_engine")
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
        if result.provider_failure_class:
            self._apply_provider_failure_marker(state, result)
            return
        if result.admission_failure_class:
            self._apply_p6_token_admission_result(state, result)
            self._update_candidate_ledger(state, raw_issue)
            return
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
        raw_issue["proof_kernel_mode"] = self._PROOF_KERNEL_TERMINAL_MODE
        raw_issue["proof_kernel_terminal_authority_decision"] = (
            self._proof_kernel_terminal_decision(raw_issue)
        )
        authority = self._evaluate_bound_terminal_authority(
            raw_issue,
            model_result=val_data,
            has_executable_action=False,
            protocol_or_engine_failure=False,
        )
        raw_issue["terminal_authority_decision"] = authority.to_dict()
        raw_issue["terminal_authority"] = authority.authority
        raw_issue["terminal_reason_codes"] = [authority.reason_code]
        if authority.disposition in {"confirmed", "rejected_with_proof"}:
            transition_level = str(raw_issue.get("terminal_transition_level") or "") or {
                "initial": "V1",
                "evidence_recheck": "V2",
                "investigation_synthesis": "V3",
            }.get(str(val_data.get("pass") or "initial"), "V1")
            self._mark_terminal_transition(raw_issue, transition_level, authority)
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
        elif authority.disposition == "confirmed":
            outcome = self._validation_outcome_from_proof_authority(raw_issue, authority)
        elif authority.disposition == "rejected_with_proof":
            outcome = self._validation_outcome_from_proof_authority(raw_issue, authority)
        raw_issue["policy_disposition"] = str(
            raw_issue.get("candidate_disposition") or outcome.memory_status or "needs_review"
        )
        self._record_validator_attribution(raw_issue, val_data, outcome)
        outcome = self._classify_final_needs_review(state, raw_issue, outcome)
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)
        if outcome.memory_status:
            self.remember_validation_result(raw_issue, outcome.memory_status)
        self._update_candidate_ledger(state, raw_issue)
        self._log_validation_outcome(raw_issue, val_data, verdict, outcome.final_score)

    def _apply_provider_failure_marker(
        self,
        state: Dict[str, Any],
        result: _ValidationWorkerResult,
    ) -> None:
        """Retain one body-free provider failure as an unresolved obligation.

        Successful siblings in the same admitted batch are applied normally.
        This issue remains in ``pending_new_issues`` so a bounded resume can
        request only the failed/unstarted obligations; it is not projected as
        a finding, an audit observation, or an engine-produced terminal.
        """

        failure_class = str(result.provider_failure_class or "")
        issue = result.raw_issue
        issue["validation_provider_failure_class"] = failure_class
        issue["validation_provider_failure_count"] = 1
        counts = state.setdefault("validation_provider_failure_counts", {})
        if isinstance(counts, dict):
            counts[failure_class] = int(counts.get(failure_class, 0) or 0) + 1
        state["validation_provider_failure_count"] = (
            int(state.get("validation_provider_failure_count", 0) or 0) + 1
        )
        state["validation_provider_failure_settled_count"] = (
            int(state.get("validation_provider_failure_settled_count", 0) or 0) + 1
        )
        self._trace_event(
            issue,
            stage="validation",
            actor="provider_runtime",
            reason_code="VALIDATION_PROVIDER_FAILURE",
            details={"failure_class": failure_class, "failure_count": 1},
            dedupe_key=(
                f"validation-provider-failure:{failure_class}:" f"{self._trace_cluster_uid(issue)}"
            ),
        )

    def _apply_p6_token_admission_result(
        self,
        state: Dict[str, Any],
        result: _ValidationWorkerResult,
    ) -> None:
        """Close one pre-provider P6 budget refusal without engine failure.

        A soft refusal is authorized only for work already classified by the
        answer-free scheduler as low-value audit.  It must still pass through
        the same answer-free audit-eligibility classifier as completed
        Validator work: an eligible unresolved obligation remains canonical
        ``needs_review`` while an ineligible hint is conserved as audit-only.
        A hard refusal always leaves the unstarted obligation canonical
        ``needs_review``.  Neither path calls a provider, exposes an exception
        body, nor forges proof closure.
        """

        issue = result.raw_issue
        failure_class = str(result.admission_failure_class or "")
        # Only the sealed ledger can issue a soft-watermark refusal, and it
        # does so exclusively for the fixed low-value call-kind allowlist.
        # Rechecking mutable candidate priority here would create a second,
        # potentially divergent authority after provider admission.
        soft_audit = failure_class == "p6_token_soft_watermark"
        issue.pop("model_verdict", None)
        issue["p6_token_admission_reason"] = failure_class
        issue["p6_token_admission_request_denied"] = result.admission_request_denied
        issue["p6_token_provider_calls"] = 0
        issue["proof_kernel_mode"] = self._PROOF_KERNEL_TERMINAL_MODE
        authority = self._evaluate_bound_terminal_authority(issue, operation="live")
        issue["proof_kernel_terminal_authority_decision"] = authority.to_dict()
        issue["terminal_authority_decision"] = authority.to_dict()
        issue["terminal_authority"] = authority.authority
        issue["terminal_reason_codes"] = [authority.reason_code]
        issue["candidate_disposition"] = "needs_review"
        issue["policy_disposition"] = "needs_review"
        issue["validation_status"] = "needs_review"
        issue["finding_kind"] = "needs_review"
        outcome = ValidationOutcome(
            report_bucket="observations",
            memory_status="needs_review",
            verdict="needs_review",
            final_score=0.0,
        )
        if soft_audit:
            outcome = self._classify_final_needs_review(state, issue, outcome)
        if outcome.report_bucket:
            bucket = state.setdefault(outcome.report_bucket, [])
            if isinstance(bucket, list) and not any(value is issue for value in bucket):
                bucket.append(issue)
        if outcome.memory_status:
            self.remember_validation_result(issue, outcome.memory_status)
        counts = state.setdefault("p6_token_admission_counts", {})
        if isinstance(counts, dict):
            counts[failure_class] = int(counts.get(failure_class, 0) or 0) + 1
        if result.admission_request_denied:
            denied = state.setdefault("p6_token_admission_denied_request_counts", {})
            if isinstance(denied, dict):
                denied[failure_class] = int(denied.get(failure_class, 0) or 0) + 1
        self._trace_event(
            issue,
            stage="validation",
            actor="p6_balanced_token_admission",
            reason_code=("P6_TOKEN_SOFT_WATERMARK" if soft_audit else "P6_TOKEN_HARD_LIMIT"),
            details={
                "failure_class": failure_class,
                "admission_request_denied": result.admission_request_denied,
                "provider_calls": 0,
                "terminal_disposition": str(issue.get("candidate_disposition") or ""),
            },
            dedupe_key=(f"p6-token-admission:{failure_class}:" f"{self._trace_cluster_uid(issue)}"),
        )

    @staticmethod
    def _record_validator_attribution(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        outcome: ValidationOutcome,
    ) -> None:
        attribution = issue.get("attribution")
        if not isinstance(attribution, dict):
            attribution = {
                "schema_version": "zscope.finding-attribution.v2",
                "discovered_by": [],
                "discovery_details": [],
            }
            issue["attribution"] = attribution
        policy_disposition = str(
            issue.get("candidate_disposition") or outcome.memory_status or "needs_review"
        )
        authority = issue.get("terminal_authority_decision")
        proof_engine_terminal = (
            isinstance(authority, Mapping)
            and str(authority.get("authority") or "").startswith("zscope.proof-checker")
            and authority.get("terminal") is True
        )
        fail_closed_rule_disposition = (
            isinstance(authority, Mapping)
            and str(authority.get("schema_version") or "") == TERMINAL_AUTHORITY_DECISION_V4
            and authority.get("terminal") is True
            and str(authority.get("disposition") or "") == "needs_review"
            and str(issue.get("candidate_kind") or "") in {"backend_signal", "deterministic_rule"}
        )
        if proof_engine_terminal or fail_closed_rule_disposition:
            # Rule/runtime signals still pass through ProofKernel's fail-closed
            # disposition even when a legacy model verdict or v3 proof cannot
            # authorize a terminal confirmation.  ``candidate_disposition``
            # and the empty terminal transition below retain that distinction.
            attribution["decided_by"] = "proof_engine"
        else:
            # A model attempt is not itself a final decision.  In particular,
            # rejected/uncertain output without a deterministic contradiction
            # remains an unresolved, user-visible review obligation.
            attribution["decided_by"] = "unresolved"
        result_pass = str(val_data.get("pass") or "initial")
        attempt_level = {
            "initial": "V1",
            "evidence_recheck": "V2",
            "investigation_synthesis": "V3",
        }.get(result_pass, "V1")
        attribution["decision_level"] = "none"
        if attribution["decided_by"] == "proof_engine":
            transition_level = str(issue.get("terminal_transition_level") or "")
            attribution["decision_level"] = (
                transition_level if transition_level in {"V0", "V1", "V2", "V3"} else "V0"
            )
        issue["validator_policy_outcome"] = {
            "model_verdict": validation_verdict(val_data),
            "policy_disposition": policy_disposition,
            "decision_level": attribution["decision_level"],
            "attempt_level": attempt_level,
            "terminal_transition_level": str(issue.get("terminal_transition_level") or ""),
        }

    def _mark_terminal_transition(
        self,
        issue: Dict[str, Any],
        level: str,
        authority: Any,
    ) -> bool:
        """Freeze and persist the first program-authorized v4 transition."""

        if str(level) not in {"V0", "V1", "V2", "V3"}:
            return False
        disposition = str(getattr(authority, "disposition", "") or "")
        terminal = bool(getattr(authority, "terminal", False))
        if not terminal or disposition not in {"confirmed", "rejected_with_proof"}:
            return False
        authority_dict = authority.to_dict()
        issue["terminal_authority_decision"] = dict(authority_dict)
        issue["proof_kernel_terminal_authority_decision"] = dict(authority_dict)
        _, created = self._decision_trace_store.record_terminal_transition(
            issue,
            level=str(level),
            authority=authority_dict,
        )
        return created

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

    def _v2_request_identity(
        self,
        item: _PreparedValidation,
        raw_request: Mapping[str, Any],
    ) -> tuple[str, Dict[str, Any]]:
        """Bind a V2 request to its exact parameters and current evidence snapshot.

        A fact kind is a provider routing key, not a request identity.  Keeping
        the subject, function, fixed action parameters, and the evidence slice
        seen by the requesting model lets an exact duplicate be a zero-call
        transition while a refined request of the same kind remains runnable.
        """

        fact_kind = str(raw_request.get("fact_kind") or "").strip().lower()
        subject_uid = str(raw_request.get("subject_uid") or "").strip()
        function_uid = str(raw_request.get("function_uid") or "").strip()
        explicit = raw_request.get("fixed_parameters")
        fixed_parameters: Any = dict(explicit) if isinstance(explicit, Mapping) else None
        if fixed_parameters is None:
            fixed_parameters = self._parameterized_action_parameters(
                item.raw_issue,
                item.evidence_pack,
                fact_kind=fact_kind,
                subject_uid=subject_uid,
            )

        evidence_snapshot_sha256 = self._current_v2_evidence_snapshot_sha256(item)
        payload = {
            "fact_kind": fact_kind,
            "subject_uid": subject_uid,
            "function_uid": function_uid,
            "fixed_parameters": fixed_parameters,
            "evidence_snapshot_sha256": evidence_snapshot_sha256,
        }
        return self._stable_hash(payload), payload

    def _current_v2_evidence_snapshot_sha256(
        self,
        item: _PreparedValidation,
    ) -> str:
        """Commit the material evidence currently available to V2.

        The initial Validator slice is an immutable base, but it is not the
        complete identity after deterministic providers or V3 actions add a
        fact.  Derive the current snapshot from the accepted decision facts,
        producer-verified proofs, and the exact live ProofKernel selection.
        Operational bookkeeping (provider status, missing-plan scheduling,
        retry counters) is deliberately excluded: a ``no_match`` transition
        must not manufacture a new evidence identity and unlock another call.
        """

        issue = item.raw_issue
        snapshots = issue.get("validator_evidence_snapshot_sha256_by_pass")
        if not isinstance(snapshots, dict):
            snapshots = {}
            issue["validator_evidence_snapshot_sha256_by_pass"] = snapshots
        observed_initial_sha256 = str(snapshots.get("initial") or "")
        if not observed_initial_sha256:
            observed_initial_sha256 = self._stable_hash(
                {
                    "decision_fact_slice": issue.get("decision_fact_slice") or {},
                    "evidence_pack": item.evidence_pack,
                }
            )
        initial_sha256 = str(snapshots.get("v2_initial_base") or "")
        if not initial_sha256:
            initial_sha256 = observed_initial_sha256
            snapshots["v2_initial_base"] = initial_sha256
        elif observed_initial_sha256 != initial_sha256:
            # The V1 slice is immutable after its first identity projection.
            # Only accepted material below may authorize a refined request.
            snapshots["v2_initial_snapshot_drift"] = True

        fact_slice = issue.get("decision_fact_slice")
        fact_slice = fact_slice if isinstance(fact_slice, Mapping) else {}
        proof_input = issue.get("proof_kernel_input")
        proof_input = proof_input if isinstance(proof_input, Mapping) else {}

        def canonical_records(value: Any) -> list[Dict[str, Any]]:
            records = {
                self._stable_hash(record): deepcopy(dict(record))
                for record in value or []
                if isinstance(record, Mapping)
            }
            return [records[digest] for digest in sorted(records)]

        material = {
            "schema_version": "zscope.v2-evidence-snapshot.v1",
            "initial_validator_snapshot_sha256": initial_sha256,
            "decision_facts": canonical_records(fact_slice.get("facts")),
            "decision_fact_uids": sorted(
                str(value) for value in fact_slice.get("fact_uids") or [] if str(value)
            ),
            "dependency_code_hashes": sorted(
                str(value) for value in fact_slice.get("dependency_code_hashes") or [] if str(value)
            ),
            "v3_investigation_facts": canonical_records(issue.get("v3_investigation_facts")),
            "deterministic_proofs": canonical_records(issue.get("deterministic_proofs")),
            "proof_kernel_input_sha256": (self._stable_hash(proof_input) if proof_input else ""),
            "proof_kernel_live_selected_action_uids": list(
                map(str, issue.get("proof_kernel_live_selected_action_uids") or [])
            ),
        }
        current_sha256 = self._stable_hash(material)
        snapshots["current_v2"] = current_sha256
        return current_sha256

    def _parameterized_action_parameters(
        self,
        issue: Mapping[str, Any],
        evidence_pack: Mapping[str, Any],
        *,
        fact_kind: str,
        subject_uid: str,
    ) -> list[Dict[str, Any]]:
        """Return the deterministic fixed-parameter catalog for one request scope."""

        action_parameters: list[Dict[str, Any]] = []
        try:
            actions = self._fact_capabilities.executable_actions(
                issue,
                evidence_pack,
                (fact_kind,),
            )
        except Exception:
            actions = ()
        for action in actions:
            if subject_uid and action.subject_uid and action.subject_uid != subject_uid:
                continue
            action_parameters.append(dict(action.fixed_parameters))
        return sorted(
            action_parameters,
            key=lambda value: json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ),
        )

    def _fact_first_parameterized_request_scope(
        self,
        issue: Mapping[str, Any],
        evidence_pack: Mapping[str, Any],
        fact_kind: str,
    ) -> Dict[str, Any]:
        """Describe the exact parameter scope already exercised by fact-first.

        The shadow sweep predates a model request, so it has no model evidence
        snapshot yet.  Subject, function, and fixed parameters are nevertheless
        deterministic.  The first matching V1 snapshot is bound when the model
        asks for that exact scope; a different subject/function/parameter set is
        therefore never hidden behind the shadow attempt.
        """

        normalized_kind = str(fact_kind or "").strip().lower()
        function_uid = str(
            issue.get("function_signature")
            or issue.get("function")
            or issue.get("function_name")
            or ""
        ).strip()
        obligation = issue.get("security_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        if normalized_kind == "caller_contract":
            # Caller contracts are function-scoped.  Treating the detector's
            # structured source identity as a distinct subject would rerun the
            # same function-level provider after V1.
            subject_uid = function_uid
        else:
            subject_uid = str(
                issue.get("resource_identity")
                or issue.get("source_identity")
                or obligation.get("subject_uid")
                or ""
            ).strip()
        return {
            "fact_kind": normalized_kind,
            "subject_uid": subject_uid,
            "function_uid": function_uid,
            "fixed_parameters": self._parameterized_action_parameters(
                issue,
                evidence_pack,
                fact_kind=normalized_kind,
                subject_uid=subject_uid,
            ),
        }

    def _matches_fact_first_parameterized_request(
        self,
        issue: Dict[str, Any],
        *,
        identity_sha256: str,
        identity: Mapping[str, Any],
    ) -> bool:
        """Bind and recognize one no-increment request already run in shadow.

        Only the first V1 evidence snapshot may inherit a fact-first attempt.
        Once bound, any changed evidence snapshot is a refined request and is
        allowed to execute even when its fact kind and object are unchanged.
        """

        shadow = issue.get("proof_kernel_fact_first")
        shadow = shadow if isinstance(shadow, Mapping) else {}
        scopes = shadow.get("parameterized_request_scopes")
        if not isinstance(scopes, list):
            return False
        request_scope = {
            key: deepcopy(identity.get(key))
            for key in ("fact_kind", "subject_uid", "function_uid", "fixed_parameters")
        }
        matching_scope = next(
            (
                dict(value)
                for value in scopes
                if isinstance(value, Mapping)
                and all(value.get(key) == request_scope.get(key) for key in request_scope)
            ),
            None,
        )
        if matching_scope is None:
            return False
        scope_sha256 = self._stable_hash(request_scope)
        baselines = issue.setdefault("fact_first_parameterized_request_baselines", [])
        if not isinstance(baselines, list):
            baselines = []
            issue["fact_first_parameterized_request_baselines"] = baselines
        existing = next(
            (
                value
                for value in baselines
                if isinstance(value, Mapping)
                and str(value.get("scope_sha256") or "") == scope_sha256
            ),
            None,
        )
        if existing is None:
            baselines.append(
                {
                    "scope_sha256": scope_sha256,
                    "identity_sha256": identity_sha256,
                    "evidence_snapshot_sha256": str(identity.get("evidence_snapshot_sha256") or ""),
                }
            )
            return True
        return str(existing.get("identity_sha256") or "") == identity_sha256

    @staticmethod
    def _legacy_fact_request_hash(issue: Mapping[str, Any], request: Mapping[str, Any]) -> str:
        """Return the pre-v2 queue key so refined requests can bypass kind-level history."""

        return hashlib.sha256(
            json.dumps(
                {
                    "cluster": str(issue.get("validation_cluster_uid") or ""),
                    "fact_kind": str(request.get("fact_kind") or "").strip().lower(),
                    "subject_uid": str(request.get("subject_uid") or ""),
                    "function_uid": str(request.get("function_uid") or ""),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _begin_v2_request_attempt(
        issue: Dict[str, Any],
        *,
        identity_sha256: str,
        identity: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        attempts = issue.setdefault("validator_fact_request_attempts", [])
        if not isinstance(attempts, list):
            attempts = []
            issue["validator_fact_request_attempts"] = attempts
        if any(
            isinstance(value, Mapping)
            and str(value.get("identity_sha256") or "") == identity_sha256
            for value in attempts
        ):
            return None
        record = {
            "identity_sha256": identity_sha256,
            **dict(identity),
            "status": "started",
        }
        attempts.append(record)
        return record

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

    def _classify_final_needs_review(
        self,
        state: Dict[str, Any],
        issue: Dict[str, Any],
        outcome: ValidationOutcome,
    ) -> ValidationOutcome:
        """Separate actionable review obligations before report projection.

        This answer-free classifier runs after product validation but before a
        candidate enters either the report bucket or terminal ledger.  Audit
        observations remain terminally accounted for without inflating the
        user-actionable ``with-needs-review`` view.
        """

        disposition = str(issue.get("candidate_disposition") or outcome.memory_status or "")
        if disposition != "needs_review" or outcome.memory_status == "engine_failed":
            return outcome
        has_v4_envelope = bool(
            isinstance(issue.get("proof_kernel_frozen_state"), Mapping)
            and isinstance(issue.get("proof_kernel_closure_evaluation"), Mapping)
        )
        # Outside the sealed P6 admission mode, retain compatibility for old
        # reports/checkpoints that predate the v4 proof envelope.  P6 has no
        # such escape hatch: every unresolved candidate must satisfy the same
        # answer-free eligibility contract before entering the actionable
        # with-needs-review view.  Missing or malformed v4 inputs therefore
        # evaluate as unqualified and are terminally conserved as audit-only.
        if not has_v4_envelope and not self._p6_balanced_admission_enabled():
            return outcome
        evaluation = evaluate_audit_eligibility(issue)
        issue["audit_eligibility"] = evaluation.to_dict()
        if evaluation.needs_review_eligible:
            return outcome
        issue["candidate_disposition"] = "shadow_observation"
        issue["policy_disposition"] = "shadow_observation"
        issue["validation_status"] = "uncertain"
        issue["finding_kind"] = "audit_only"
        issue["audit_status"] = "audit_only"
        issue["audit_reason_codes"] = list(evaluation.reason_codes)
        existing_reasons = [
            str(value) for value in issue.get("terminal_reason_codes") or [] if str(value)
        ]
        issue["terminal_reason_codes"] = list(
            dict.fromkeys([*existing_reasons, *evaluation.reason_codes])
        )
        policy = issue.get("validator_policy_outcome")
        if isinstance(policy, dict):
            policy["policy_disposition"] = "shadow_observation"
        audit = state.setdefault("audit_observations", [])
        if isinstance(audit, list) and not any(value is issue for value in audit):
            audit.append(issue)
        state["audit_observation_count"] = int(state.get("audit_observation_count", 0) or 0) + 1
        return ValidationOutcome(
            report_bucket=None,
            memory_status=None,
            verdict="uncertain",
            final_score=outcome.final_score,
        )

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
        if not requested_kind or not isinstance(raw_request, Mapping):
            item.raw_issue["validator_fact_resolution"] = {
                "fact_kinds": [requested_kind] if requested_kind else [],
                "statuses": [],
                "status": "no_parameterized_request",
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
                    "request_identity": "",
                },
                dedupe_key=(
                    f"v2-skipped-no-request:{requested_kind or 'no-request'}:"
                    f"{self._trace_cluster_uid(item.raw_issue)}"
                ),
            )
            return val_data
        request_identity_sha256, request_identity = self._v2_request_identity(
            item,
            raw_request,
        )
        if self._matches_fact_first_parameterized_request(
            item.raw_issue,
            identity_sha256=request_identity_sha256,
            identity=request_identity,
        ):
            attempt = self._begin_v2_request_attempt(
                item.raw_issue,
                identity_sha256=request_identity_sha256,
                identity=request_identity,
            )
            if attempt is not None:
                attempt["status"] = "fact_first_no_new_evidence"
                attempt["evidence_delta_hash"] = ""
            item.raw_issue["validator_fact_resolution"] = {
                "fact_kinds": [requested_kind],
                "statuses": ["prevalidated_no_new_evidence"],
                "status": "no_new_parameterized_request",
                "request_identity_sha256": request_identity_sha256,
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
                    "request_identity_sha256": request_identity_sha256,
                    "duplicate_scope": "fact_first_parameterized_request",
                },
                dedupe_key=f"v2-fact-first-no-new:{request_identity_sha256}",
            )
            return val_data
        attempt = self._begin_v2_request_attempt(
            item.raw_issue,
            identity_sha256=request_identity_sha256,
            identity=request_identity,
        )
        if attempt is None:
            item.raw_issue["validator_fact_resolution"] = {
                "fact_kinds": [requested_kind],
                "statuses": ["duplicate_request"],
                "status": "exact_duplicate_request",
                "request_identity_sha256": request_identity_sha256,
                "evidence_delta_hash": "",
                "proof_added": False,
            }
            item.raw_issue["validator_v2_stop_reason"] = "duplicate_fact_request"
            self._trace_event(
                item.raw_issue,
                stage="V2",
                actor="validation_runner",
                reason_code="V2_SKIPPED_NO_DELTA",
                details={
                    "requested_fact_kind": requested_kind,
                    "request_identity_sha256": request_identity_sha256,
                    "duplicate_scope": "exact_parameterized_request",
                },
                dedupe_key=f"v2-exact-duplicate:{request_identity_sha256}",
            )
            return val_data

        # EvidenceCompletionQueue predates the parameterized identity and
        # remembers only cluster/kind/subject/function.  Remove that narrower
        # key for a genuinely new snapshot/parameter request; the runner's
        # stronger identity above remains the authoritative duplicate guard.
        legacy_hash = self._legacy_fact_request_hash(item.raw_issue, raw_request)
        legacy_attempts = item.raw_issue.get("evidence_completion_request_hashes")
        if isinstance(legacy_attempts, list):
            item.raw_issue["evidence_completion_request_hashes"] = [
                value for value in legacy_attempts if str(value) != legacy_hash
            ]
        try:
            batch = self._evidence_completion_queue.resolve_required_facts(
                item.raw_issue,
                validator_data=val_data,
                validation_evidence=item.evidence_pack,
                fact_kinds_override=(requested_kind,),
            )
        except Exception:
            logger.warning(
                "Required fact resolution failed for candidate %s class=%s",
                item.raw_issue.get("candidate_uid") or item.raw_issue.get("id"),
                "deterministic_fact_provider_failed",
            )
            attempt["status"] = "provider_error"
            item.raw_issue["validator_fact_resolution"] = {
                "status": "provider_error",
                "request_identity_sha256": request_identity_sha256,
                "failure_class": "deterministic_fact_provider_failed",
            }
            item.raw_issue["validator_v2_stop_reason"] = "unsupported_fact"
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                stop_reason="unsupported_fact",
                reasoning="The required deterministic fact providers failed.",
            )

        statuses = [value.terminal_status for value in batch.resolutions]
        attempt["status"] = (
            "resolved" if batch.has_evidence_delta else (statuses[0] if statuses else "no_match")
        )
        attempt["evidence_delta_hash"] = batch.evidence_delta_hash
        # EvidenceCompletionQueue facts may refine the next model slice, but
        # they are not a replacement proof obligation.  Only an exact mapping
        # back into and re-evaluation of the original ``proof_kernel_input``
        # may create a v4 promotion.
        frozen_action_uid = self._matching_frozen_v2_action_uid(
            item.raw_issue,
            request_identity=request_identity,
            evidence_delta=batch.evidence_delta,
        )
        if frozen_action_uid:
            self._reenter_frozen_proof_obligation(
                item.raw_issue,
                action_uid=frozen_action_uid,
            )
            item.raw_issue["proof_kernel_v2_reentry_status"] = "reduced_original_obligation"
        elif batch.has_evidence_delta:
            item.raw_issue["proof_kernel_v2_reentry_status"] = "no_exact_action_in_frozen_catalog"
        proof_authority = self._evaluate_bound_terminal_authority(item.raw_issue)
        proof_is_terminal = bool(
            proof_authority.terminal
            and proof_authority.disposition in {"confirmed", "rejected_with_proof"}
        )
        item.raw_issue["validator_fact_resolution"] = {
            "fact_kinds": [value.fact_kind for value in batch.resolutions],
            "statuses": statuses,
            "status": str(item.raw_issue.get("evidence_completion_status") or "not_applicable"),
            "request_identity_sha256": request_identity_sha256,
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
                required=proof_is_terminal,
            )
        if proof_is_terminal:
            token_metadata["validator_fact_resolution_proof_count"] = (
                int(token_metadata.get("validator_fact_resolution_proof_count", 0) or 0) + 1
            )
            item.raw_issue["validator_v2_stop_reason"] = "decision_complete"
            proof_disposition = str(proof_authority.disposition or "")
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
                required=True,
            )
            self._mark_terminal_transition(item.raw_issue, "V2", proof_authority)
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                stop_reason="decision_complete",
                reasoning=(
                    "The original frozen proof obligation closed after fact resolution; "
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
        investigate_kwargs: Dict[str, Any] = {
            "max_iterations": item.v3_max_iterations or 50,
        }
        supports_evidence_actions = {
            parameter.name for parameter in inspect.signature(investigate).parameters.values()
        }.issuperset({"evidence_actions", "evidence_action_executor"})
        action_by_id = {value.action_id: value for value in actions}
        executed_v3_action_ids: List[str] = []
        pending_v3_terminal: Optional[Dict[str, Any]] = None
        post_terminal_action_attempted = False
        if supports_evidence_actions:

            def execute_evidence_action(action_id: str) -> Dict[str, Any]:
                nonlocal pending_v3_terminal
                nonlocal post_terminal_action_attempted
                if pending_v3_terminal is not None:
                    post_terminal_action_attempted = True
                    return {
                        "status": "unknown",
                        "reason_code": "post_terminal_action_forbidden",
                        "verified_fact": None,
                        "newly_accepted": False,
                        "terminal_authority": pending_v3_terminal["authority"].to_dict(),
                    }
                current_authority = self._evaluate_bound_terminal_authority(item.raw_issue)
                if current_authority.disposition in {"confirmed", "rejected_with_proof"}:
                    pending_v3_terminal = {
                        "authority": current_authority,
                        "cause_refs": (),
                        "action_id": "",
                        "usage_call_ids": tuple(
                            str(value.get("call_id") or "")
                            for value in self._cluster_usage_events(item.raw_issue)[usage_start:]
                            if str(value.get("call_id") or "")
                        ),
                        "executed_action_ids": tuple(executed_v3_action_ids),
                    }
                    return {
                        "status": "unknown",
                        "reason_code": "terminal_authority_already_closed",
                        "verified_fact": None,
                        "newly_accepted": False,
                        "terminal_authority": current_authority.to_dict(),
                    }
                action = action_by_id.get(str(action_id or ""))
                if action is None:
                    return {
                        "status": "unknown",
                        "reason_code": "unknown_evidence_action",
                        "verified_fact": None,
                    }
                executed_v3_action_ids.append(action.action_id)
                remaining_before = set(self._remaining_fact_kinds(item.raw_issue))
                if action.fact_kind not in remaining_before:
                    authority = self._evaluate_bound_terminal_authority(
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
                proof_refs = []
                for artifact_kind, artifact in (result.proof_artifacts or {}).items():
                    proof_refs.append(
                        self._decision_trace_store.put_evidence(
                            kind=artifact_kind,
                            payload=artifact,
                            producer="zscope.proof-kernel.v4",
                            dependency_hashes=tuple(
                                str(value)
                                for value in artifact.get("dependency_hashes") or []
                                if str(value)
                            ),
                        )
                    )
                if proof_refs:
                    existing_refs = item.raw_issue.setdefault(
                        "validator_v3_fact_proof_artifact_refs", []
                    )
                    if not isinstance(existing_refs, list):
                        existing_refs = []
                        item.raw_issue["validator_v3_fact_proof_artifact_refs"] = existing_refs
                    existing_refs.extend(
                        value for value in proof_refs if value not in existing_refs
                    )
                    checker = (result.proof_artifacts or {}).get("proof_check_result")
                    if isinstance(checker, Mapping):
                        checker_results = item.raw_issue.setdefault(
                            "validator_v3_fact_checker_results", []
                        )
                        if not isinstance(checker_results, list):
                            checker_results = []
                            item.raw_issue["validator_v3_fact_checker_results"] = checker_results
                        checker_results.append(dict(checker))
                fact = result.fact
                added = 0
                if isinstance(fact, dict):
                    added = self._apply_v3_investigation_facts(
                        item.raw_issue,
                        {"evidence_refs": [str(fact.get("fact_uid") or "")]},
                        {"validator_investigation_facts": [fact]},
                    )
                if added:
                    frozen_action_uid = self._matching_frozen_proof_action_uid(
                        item.raw_issue,
                        action,
                        item.evidence_pack,
                    )
                    if frozen_action_uid:
                        self._reenter_frozen_proof_obligation(
                            item.raw_issue,
                            action_uid=frozen_action_uid,
                        )
                    else:
                        item.raw_issue["proof_kernel_v3_reentry_status"] = (
                            "no_exact_action_in_frozen_catalog"
                        )
                authority = self._evaluate_bound_terminal_authority(
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
                proof_is_terminal = bool(
                    authority.terminal
                    and authority.disposition in {"confirmed", "rejected_with_proof"}
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
                    output_refs=(certificate_ref, *proof_refs),
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
                if proof_is_terminal:
                    pending_v3_terminal = {
                        "authority": authority,
                        "cause_refs": (certificate_ref, *proof_refs),
                        "action_id": action.action_id,
                        "usage_call_ids": tuple(
                            str(value.get("call_id") or "")
                            for value in self._cluster_usage_events(item.raw_issue)[usage_start:]
                            if str(value.get("call_id") or "")
                        ),
                        "executed_action_ids": tuple(executed_v3_action_ids),
                    }
                payload = result.to_dict()
                payload["certificate_ref"] = certificate_ref
                payload["proof_artifact_refs"] = proof_refs
                payload["newly_accepted"] = bool(added)
                payload["terminal_authority"] = authority.to_dict()
                return payload

            investigate_kwargs["evidence_actions"] = [value.to_dict() for value in actions]
            investigate_kwargs["evidence_action_executor"] = execute_evidence_action
        response = investigate(investigation_input, **investigate_kwargs)
        self._merge_response_metadata(
            token_metadata,
            getattr(response, "metadata", {}) or {},
        )
        selected_action_ids = tuple(executed_v3_action_ids)

        def bind_pending_terminal(structured_output: Dict[str, Any]) -> bool:
            """Bind the terminal-producing call, then freeze the proof boundary."""

            if pending_v3_terminal is None:
                return False
            observed_usage_call_ids = tuple(
                str(value.get("call_id") or "")
                for value in self._cluster_usage_events(item.raw_issue)[usage_start:]
                if str(value.get("call_id") or "")
            )
            if (
                post_terminal_action_attempted
                or observed_usage_call_ids != pending_v3_terminal["usage_call_ids"]
                or selected_action_ids != pending_v3_terminal["executed_action_ids"]
            ):
                raise DecisionTraceError("post_proof_call_detected")
            self._record_model_trace(
                item.raw_issue,
                stage="V3",
                structured_input=investigation_input,
                structured_output=structured_output,
                usage_start=usage_start,
                reason_code="V3_STOP_NO_REMAINING_ACTION",
                tool_call_ids=selected_action_ids,
            )
            pending_authority = pending_v3_terminal["authority"]
            self._trace_event(
                item.raw_issue,
                stage="V3",
                actor="proof_kernel",
                reason_code=(
                    "NEGATIVE_PROOF_COMPLETE"
                    if pending_authority.disposition == "rejected_with_proof"
                    else "POSITIVE_PROOF_COMPLETE"
                ),
                output_refs=tuple(pending_v3_terminal["cause_refs"]),
                details={"action_id": str(pending_v3_terminal["action_id"] or "")},
                dedupe_key=(
                    f"v3-proof:{self._trace_cluster_uid(item.raw_issue)}:"
                    f"{pending_v3_terminal['action_id'] or 'preclosed'}"
                ),
                required=True,
            )
            self._mark_terminal_transition(item.raw_issue, "V3", pending_authority)
            return True

        if not response.success or not isinstance(response.data, dict):
            if response.error:
                item.raw_issue["validator_v3_error"] = str(response.error)[:500]
            if pending_v3_terminal is not None:
                item.raw_issue["validator_v3_stop_reason"] = "decision_complete"
                terminal = self._terminal_from_prior_for_v3(
                    item,
                    val_data,
                    validation_pass="investigation_synthesis",
                    stop_reason="decision_complete",
                    reasoning=(
                        "The program-owned proof closed before the model response failed; "
                        "no post-terminal work is authorized."
                    ),
                )
                bind_pending_terminal(terminal)
            else:
                item.raw_issue["validator_v3_stop_reason"] = "investigation_exhausted"
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
                    tool_call_ids=selected_action_ids,
                )
            return terminal
        revised = dict(response.data)
        if str(revised.get("schema_version") or "") != "zscope.validator-result.v3":
            if pending_v3_terminal is not None:
                item.raw_issue["validator_v3_stop_reason"] = "decision_complete"
                terminal = self._terminal_from_prior_for_v3(
                    item,
                    val_data,
                    validation_pass="investigation_synthesis",
                    stop_reason="decision_complete",
                    reasoning=(
                        "The program-owned proof closed before malformed model output; "
                        "no post-terminal work is authorized."
                    ),
                )
                bind_pending_terminal(terminal)
            else:
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
                    tool_call_ids=selected_action_ids,
                )
            return terminal
        response_metadata = getattr(response, "metadata", {}) or {}
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
            for selected_action_id in selected_action_ids:
                selected_action = action_by_id.get(selected_action_id)
                if selected_action is None:
                    continue
                frozen_action_uid = self._matching_frozen_proof_action_uid(
                    item.raw_issue,
                    selected_action,
                    item.evidence_pack,
                )
                if frozen_action_uid:
                    self._reenter_frozen_proof_obligation(
                        item.raw_issue,
                        action_uid=frozen_action_uid,
                    )
            usage_ledger = getattr(self.config, "scan_token_usage_ledger", None)
            attribute_facts = getattr(usage_ledger, "attribute_accepted_facts", None)
            if callable(attribute_facts):
                attribute_facts(
                    validation_cluster_uid=str(item.raw_issue.get("validation_cluster_uid") or ""),
                    new_fact_count=accepted_fact_count,
                )
        model_trace_recorded = False
        if pending_v3_terminal is not None:
            model_trace_recorded = bind_pending_terminal(revised)
        elif isinstance(revised.get("missing_fact_request"), Mapping):
            self._record_model_trace(
                item.raw_issue,
                stage="V3",
                structured_input=investigation_input,
                structured_output=revised,
                usage_start=usage_start,
                reason_code="V3_STOP_NO_REMAINING_ACTION",
                tool_call_ids=selected_action_ids,
            )
            model_trace_recorded = True
        if pending_v3_terminal is None:
            revised = self._reconcile_v3_missing_fact(
                item,
                validator_agent,
                revised,
                token_metadata,
            )
        if not model_trace_recorded:
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
                tool_call_ids=selected_action_ids,
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

    def _reconcile_v3_missing_fact(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Close a new V3 fact request once, never with contradictory state."""

        current_authority = self._evaluate_bound_terminal_authority(item.raw_issue)
        if current_authority.disposition in {"confirmed", "rejected_with_proof"}:
            self._mark_terminal_transition(item.raw_issue, "V3", current_authority)
            item.raw_issue["validator_v3_post_resolution"] = {
                "status": "skipped_terminal_authority",
                "fact_kind": "",
                "proof_added": True,
            }
            return self._terminal_from_prior_for_v3(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="decision_complete",
                reasoning="The frozen proof obligation closed before any post-terminal work.",
            )
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
        except Exception:
            item.raw_issue["validator_v3_post_resolution"] = {
                "status": "provider_error",
                "fact_kind": fact_kind,
                "failure_class": "deterministic_fact_provider_failed",
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
        # A terminal V3 fact request refines the fact plan only.  Its legacy
        # single-clause proof record must not replace or be accumulated across
        # the original composite obligation.  A replayable result may re-enter
        # only through one exact action in that frozen obligation.
        _, request_identity = self._v2_request_identity(item, raw_request)
        frozen_action_uid = self._matching_frozen_v2_action_uid(
            item.raw_issue,
            request_identity=request_identity,
            evidence_delta=batch.evidence_delta,
        )
        if frozen_action_uid:
            self._reenter_frozen_proof_obligation(
                item.raw_issue,
                action_uid=frozen_action_uid,
            )
            item.raw_issue["proof_kernel_v3_reentry_status"] = "reduced_original_obligation"
        elif batch.has_evidence_delta:
            item.raw_issue["proof_kernel_v3_reentry_status"] = "no_exact_action_in_frozen_catalog"
        proof_authority = self._evaluate_bound_terminal_authority(item.raw_issue)
        proof_is_terminal = bool(
            proof_authority.terminal
            and proof_authority.disposition in {"confirmed", "rejected_with_proof"}
        )
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
            require_persistence=proof_is_terminal,
        )
        for value in batch.resolutions:
            status = str(value.terminal_status or value.status or "").lower()
            self._trace_event(
                item.raw_issue,
                stage="provider",
                actor="evidence_completion_queue",
                reason_code={
                    "resolved": "FACT_VERIFIED_TRUE",
                    "no_match": "PROVIDER_NO_MATCH",
                    "unsupported": "FACT_UNKNOWN",
                    "timeout": "PROVIDER_TIMEOUT",
                    "provider_error": "PROVIDER_ERROR",
                    "conflicting": "FACT_CONFLICTING",
                    "duplicate_request": "FACT_UNKNOWN",
                }.get(status, "FACT_UNKNOWN"),
                output_refs=(resolution_ref,),
                details={
                    "fact_kind": value.fact_kind,
                    "status": value.status,
                    "terminal_status": value.terminal_status,
                    "miss_reason": value.miss_reason,
                },
                dedupe_key=(
                    f"v3-provider:{value.fact_kind}:{status}:"
                    f"{batch.evidence_delta_hash or 'no-delta'}"
                ),
                required=proof_is_terminal,
            )
        if proof_is_terminal:
            self._trace_event(
                item.raw_issue,
                stage="provider",
                actor="terminal_authority_evaluator",
                reason_code=(
                    "NEGATIVE_PROOF_COMPLETE"
                    if proof_authority.disposition == "rejected_with_proof"
                    else "POSITIVE_PROOF_COMPLETE"
                ),
                output_refs=(resolution_ref,),
                dedupe_key=f"v3-fact-proof:{batch.evidence_delta_hash}",
                required=True,
            )
            self._mark_terminal_transition(item.raw_issue, "V3", proof_authority)
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
        final_input = self._validator_input(
            item.raw_issue,
            item.issue_code,
            item.evidence_pack,
            validation_pass="investigation_synthesis",
            evidence_delta=batch.evidence_delta,
        )
        final_usage_start = len(self._cluster_usage_events(item.raw_issue))
        response = validator_agent.run(final_input)
        self._merge_response_metadata(token_metadata, getattr(response, "metadata", {}) or {})
        if not response.success or not isinstance(response.data, dict):
            terminal = self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="no_evidence_gain",
                reasoning="The final V3 evidence synthesis did not return a valid decision.",
            )
            self._record_model_trace(
                item.raw_issue,
                stage="V3",
                structured_input=final_input,
                structured_output=terminal,
                usage_start=final_usage_start,
                reason_code="V3_STOP_NO_REMAINING_ACTION",
            )
            return terminal
        revised = dict(response.data)
        if str(revised.get("schema_version") or "") != "zscope.validator-result.v3":
            terminal = self._terminal_uncertain_v3_result(
                item,
                val_data,
                validation_pass="investigation_synthesis",
                stop_reason="malformed_output",
                reasoning="The final V3 evidence synthesis returned a non-v3 result.",
            )
            self._record_model_trace(
                item.raw_issue,
                stage="V3",
                structured_input=final_input,
                structured_output=terminal,
                usage_start=final_usage_start,
                reason_code="V3_STOP_NO_REMAINING_ACTION",
            )
            return terminal
        self._record_model_trace(
            item.raw_issue,
            stage="V3",
            structured_input=final_input,
            structured_output=revised,
            usage_start=final_usage_start,
            reason_code="V3_STOP_NO_REMAINING_ACTION",
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
        if not self._proof_kernel_is_authoritative():
            return outcome.memory_status in {"needs_review", "engine_failed"}
        authority = self._evaluate_bound_terminal_authority(
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
    def _validation_outcome_from_proof_authority(
        issue: Dict[str, Any], authority: Any
    ) -> ValidationOutcome:
        """Project a Checker-owned terminal into the existing report buckets."""

        issue["terminal_authority_decision"] = authority.to_dict()
        issue["terminal_authority"] = authority.authority
        issue["terminal_reason_codes"] = [authority.reason_code]
        issue["candidate_disposition"] = authority.disposition
        if authority.disposition == "confirmed":
            issue["validation_status"] = "validated"
            return ValidationOutcome(
                report_bucket="issues",
                memory_status="validated",
                verdict="verified",
                final_score=1.0,
            )
        issue["validation_status"] = "rejected"
        return ValidationOutcome(
            report_bucket=None,
            memory_status="rejected",
            verdict="rejected",
            final_score=0.0,
        )

    @classmethod
    def _proof_kernel_is_authoritative(cls) -> bool:
        return cls._PROOF_KERNEL_TERMINAL_MODE == "authoritative"

    @staticmethod
    def _proof_kernel_terminal_decision(issue: Mapping[str, Any]) -> Dict[str, Any]:
        """Project only the current v4 authority; never mint a legacy live decision."""

        binding_valid = has_exact_v4_producer_occurrence_binding(issue)
        projected = TerminalAuthorityEvaluator().evaluate(issue, operation="live")
        if binding_valid or projected.disposition == "needs_review":
            return projected.to_dict()
        return (
            TerminalAuthorityEvaluator()
            .evaluate(
                issue if binding_valid else {},
                protocol_or_engine_failure=not binding_valid,
                operation="live",
            )
            .to_dict()
        )

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
        cited = {
            str(value)
            for value in val_data.get("evidence_refs") or []
            if isinstance(value, str) and value
        }
        verified_facts = []
        cited_verified_facts = []
        for fact in facts:
            fact_uid = str(fact.get("fact_uid") or "")
            locations = fact.get("locations")
            certificate = fact.get("verification_certificate")
            certificate_v2_valid = False
            if isinstance(certificate, dict):
                certificate_v2_valid = verify_certificate_v2(certificate)
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
            if certificate_action_valid:
                verified_facts.append(fact)
                if fact_uid in cited:
                    cited_verified_facts.append(fact)
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
            "reason": "fact_plan_complete" if complete else "required_facts_still_missing",
            "resolved_fact_kinds": sorted(resolved),
            "remaining_fact_kinds": remaining,
            "fact_uids": sorted(
                str(fact.get("fact_uid")) for fact in all_verified_facts if fact.get("fact_uid")
            ),
        }
        # Completing the requested fact plan is not the same as closing the
        # original proof obligation.  Promotion remains fail-closed until the
        # ProofKernel reducer issues a certificate for that frozen obligation.
        issue["fact_plan_complete"] = complete
        issue["candidate_promotion_eligible"] = False
        issue["candidate_promotion_reason"] = (
            "fact_plan_complete_requires_proof_closure"
            if complete
            else ("v3_tool_evidence_conflicting" if conflicting else "v3_tool_evidence_incomplete")
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
                "schema_version": "zscope.finding-attribution.v2",
                "discovered_by": [],
                "discovery_details": [],
            }
            raw_issue["attribution"] = attribution
        attribution["decided_by"] = "proof_engine"
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
        failure_class = "validation_worker_failure"
        logger.warning(
            "Validation failed for issue %s in function %s class=%s",
            raw_issue.get("id"),
            issue_func,
            failure_class,
        )
        outcome = self.validation_pipeline.apply_validation_failure(
            raw_issue,
            failure_class,
        )
        raw_issue.pop("proof_kernel_terminal_authority_decision", None)
        authority = self._evaluate_bound_terminal_authority(
            raw_issue,
            protocol_or_engine_failure=True,
            operation="live",
        )
        raw_issue["terminal_authority_decision"] = authority.to_dict()
        raw_issue["terminal_authority"] = authority.authority
        raw_issue["terminal_reason_codes"] = [authority.reason_code]
        self._trace_event(
            raw_issue,
            stage="policy",
            actor="zscope.proof-checker",
            reason_code="NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",
            details={"failure_class": failure_class},
            dedupe_key=f"engine-failure:{self._trace_cluster_uid(raw_issue)}",
        )
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)

    def _build_proof_engine_agent(self) -> Any:
        val_agent_cfg = next(
            (a for a in self.config.project.agents if a.name == "proof_engine"), None
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
            self.get_tools("proof_engine") if self._scan_depth() in {"balanced", "deep"} else []
        )
        return self.proof_engine_agent_factory(
            val_client,
            validator_tools,
            tool_policy=self.tool_policy_for_agent("proof_engine"),
        )

    def _validator_enabled(self) -> bool:
        return any(a.name == "proof_engine" and a.enabled for a in self.config.project.agents)

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
            snapshots = raw_issue.setdefault("validator_evidence_snapshot_sha256_by_pass", {})
            if not isinstance(snapshots, dict):
                snapshots = {}
                raw_issue["validator_evidence_snapshot_sha256_by_pass"] = snapshots
            snapshots[validation_pass] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
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
            self.attach_agent_contract(val_input, "proof_engine")
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
        self.attach_agent_contract(val_input, "proof_engine")
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
