"""Validation runner that orchestrates Validator calls and dispositions."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Lock
from typing import Any, Callable, Dict, List, Optional

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
from ...orchestration.candidate_envelope import CANDIDATE_SCHEMA_VERSION
from .evidence import (
    build_validation_evidence_pack,
    compact_validation_evidence_pack,
    compact_validation_finding,
    is_entry_root_dead_code_rejection,
    trim_code,
    validation_verdict,
)
from .pipeline import ValidationPipeline

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _PreparedValidation:
    index: int
    raw_issue: Dict[str, Any]
    issue_func: str
    issue_code: str
    evidence_pack: Dict[str, Any]


@dataclass
class _ValidationWorkerResult:
    index: int
    raw_issue: Dict[str, Any]
    issue_func: str
    success: bool
    val_data: Dict[str, Any] = field(default_factory=dict)
    error: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


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
            deadline = (
                time.monotonic() + max(0.0, float(timeout))
                if timeout is not None
                else None
            )
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


class ValidationRunner:
    """Owns validation-stage orchestration around ``ValidationPipeline``."""

    _VALIDATION_CACHE_PROTOCOL = "zscope.validator-cache.v3"
    _DEFAULT_VALIDATION_CACHE_SIZE = 4096
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
        deduplicate_issues_fn: Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]] = deduplicate_issues,
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

    def run(self, state: Dict[str, Any]) -> None:
        new_issues = state.get("pending_new_issues", [])
        if not new_issues:
            return

        deduped_issues = self._coalesce_validation_groups(new_issues)
        state["validation_group_count"] = int(
            state.get("validation_group_count", 0) or 0
        ) + len(deduped_issues)
        if len(deduped_issues) != len(new_issues):
            merged_count = len(new_issues) - len(deduped_issues)
            state["validation_group_merged_count"] = int(
                state.get("validation_group_merged_count", 0) or 0
            ) + merged_count
            logger.info("Merged %d duplicate candidate issue(s) before validation.", merged_count)
            state["notes"].append(f"Merged {merged_count} duplicate candidate issue(s) before validation.")
        new_issues = deduped_issues

        if not self._validator_enabled():
            self._mark_unvalidated(state, new_issues)
            state["pending_new_issues"] = []
            return

        prepared = []
        for index, raw_issue in enumerate(new_issues):
            item = self._prepare_issue_for_validation(state, raw_issue, index)
            if item is not None:
                prepared.append(item)

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
        token = (
            parent_token.child()
            if parent_token is not None
            else CancellationToken()
        )
        started = time.monotonic()
        try:
            with bind_cancellation_token(token):
                token.raise_if_cancelled()
                result = self._validate_prepared_issue(
                    item,
                    validator_agent=validator_agent,
                )
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
        analysis_cfg = getattr(self.config, "analysis", None)
        if analysis_cfg is None:
            return 1
        configured = getattr(analysis_cfg, "validator_workers", 0)
        if not configured:
            configured = getattr(analysis_cfg, "validation_parallel_workers", 0)
        try:
            configured_workers = int(configured or 0)
        except (TypeError, ValueError):
            configured_workers = 0
        if configured_workers > 0:
            return max(1, min(issue_count, configured_workers))

        try:
            entry_workers = int(
                getattr(analysis_cfg, "entry_workers", 0)
                or getattr(analysis_cfg, "parallel_workers", 1)
                or 1
            )
        except (TypeError, ValueError):
            entry_workers = 1
        auto_cap = 2 if entry_workers > 1 else 1
        return max(1, min(issue_count, auto_cap))

    def _mark_unvalidated(self, state: Dict[str, Any], new_issues: List[Dict[str, Any]]) -> None:
        logger.info("Validator agent disabled, marking %d issue(s) unvalidated.", len(new_issues))
        for raw_issue in new_issues:
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

    def _prepare_issue_for_validation(
        self,
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        index: int,
    ) -> Optional[_PreparedValidation]:
        issue_func = self._issue_function(raw_issue, state)
        logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)

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
        return _PreparedValidation(
            index=index,
            raw_issue=raw_issue,
            issue_func=issue_func,
            issue_code=issue_code,
            evidence_pack=evidence_pack,
        )

    def _validate_prepared_issue(
        self,
        item: _PreparedValidation,
        *,
        validator_agent: Optional[Any] = None,
    ) -> _ValidationWorkerResult:
        cache_key = ""
        cache_owner = False
        try:
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
            val_resp = validator_agent.run(
                self._validator_input(item.raw_issue, item.issue_code, item.evidence_pack)
            )
            self._merge_response_metadata(token_metadata, getattr(val_resp, "metadata", {}) or {})

            if not val_resp.success:
                return _ValidationWorkerResult(
                    index=item.index,
                    raw_issue=item.raw_issue,
                    issue_func=item.issue_func,
                    success=False,
                    error=val_resp.error,
                    metadata=token_metadata,
                )

            val_data = self._normalize_worker_response(
                item,
                validator_agent,
                val_resp.data,
                token_metadata,
            )
            self._validator_cache_put(cache_key, val_data)
            cache_owner = False
            return _ValidationWorkerResult(
                index=item.index,
                raw_issue=item.raw_issue,
                issue_func=item.issue_func,
                success=True,
                val_data=val_data,
                metadata=token_metadata,
            )
        finally:
            if cache_owner and cache_key:
                self._validator_result_cache.abandon(cache_key)
            self._close_thread_llm_sessions()

    def _validator_cache_get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        cached = self._validator_result_cache.get(cache_key)
        if cached is not None:
            return cached
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
        if isinstance(cached, dict):
            self._validator_result_cache.put(cache_key, cached)
            return dict(cached)
        return None

    def _validator_cache_put(self, cache_key: str, val_data: Dict[str, Any]) -> None:
        if not cache_key or not isinstance(val_data, dict):
            return
        self._validator_result_cache.put(cache_key, val_data)
        saver = getattr(self.snapshot_store, "save_validation_result", None)
        if not callable(saver):
            return
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
            else issue.get("evidence_pack")
            if isinstance(issue.get("evidence_pack"), dict)
            else {}
        )
        # Display IDs (for example ISSUE_1) are presentation-only and may
        # collide across entries.  Only the content-derived v3 identity can be
        # used directly; otherwise build the key from structured evidence.
        stable_id = issue.get("candidate_uid") or pack.get("candidate_uid")
        validation_cluster_uid = (
            issue.get("validation_cluster_uid")
            or pack.get("validation_cluster_uid")
        )
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
            "environment": self._validation_environment_fingerprint,
            "validation_cluster_uid": validation_cluster_uid,
            "candidate_uid": stable_id,
            "category": issue.get("defect_class") or issue.get("category") or pack.get("defect_class"),
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
        llm_ref = str(getattr(validator_cfg, "llm_ref", "") or "default")
        client = self.llm_clients.get(llm_ref) or self.llm_clients.get("default")
        payload = {
            "protocol": self._VALIDATION_CACHE_PROTOCOL,
            "project_root": project_root.resolve().as_posix(),
            "project_revision": self._project_revision(project_root),
            "index_epoch": self._index_epoch(),
            "validator_llm_ref": llm_ref,
            "llm_client": self._llm_identity(client),
            "validator_contract": getattr(validator_cfg, "contract", None),
            "validator_prompt_version": getattr(validator_cfg, "prompt_version", None),
            "tool_policy": self._tool_policy_identity(),
        }
        return self._stable_hash(payload)

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
            return " ".join(ValidationRunner._cache_component_text(item) for item in value.values()).strip()
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
        verdict = validation_verdict(val_data)
        score_data = self.validation_pipeline.score_components(raw_issue, val_data)
        outcome = self.validation_pipeline.apply_validator_result(
            raw_issue,
            val_data,
            verdict=verdict,
            score_data=score_data,
        )
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)
        if outcome.memory_status:
            self.remember_validation_result(raw_issue, outcome.memory_status)
        self._update_candidate_ledger(state, raw_issue)
        self._log_validation_outcome(raw_issue, val_data, verdict, outcome.final_score)

    @staticmethod
    def _update_candidate_ledger(
        state: Dict[str, Any],
        issue: Dict[str, Any],
    ) -> None:
        ledger = state.get("candidate_ledger")
        marker = getattr(ledger, "mark_issue_terminal", None)
        if not callable(marker):
            return
        disposition = str(
            issue.get("candidate_disposition") or "needs_review"
        ).lower()
        status = str(
            issue.get("validation_status")
            or issue.get("status")
            or disposition
        ).lower()
        marker(issue, disposition=disposition, status=status)

    def _normalize_worker_response(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        if is_entry_root_dead_code_rejection(val_data, item.evidence_pack):
            val_data = self._retry_entry_root_rejection_for_worker(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
        return val_data

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
        retry_resp = validator_agent.run(self._validator_input(raw_issue, item.issue_code, retry_pack))
        self._merge_response_metadata(token_metadata, getattr(retry_resp, "metadata", {}) or {})
        if not retry_resp.success:
            logger.warning(
                "Entry-root validation retry failed for issue %s: %s",
                raw_issue.get("id"),
                retry_resp.error,
            )
            return val_data

        retry_data = retry_resp.data
        return retry_data

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

        target["context_tokens"] = int(target.get("context_tokens", 0) or 0) + token_value("context_tokens")
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
        state["total_context_tokens"] = int(state.get("total_context_tokens", 0) or 0) + context_tokens
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
        state["prevalidation_decision_count"] = int(state.get("prevalidation_decision_count", 0) or 0) + 1
        if decision.action == "audit_observation":
            state["static_audit_observation_count"] = int(state.get("static_audit_observation_count", 0) or 0) + 1
        if decision.action == "suppress":
            state["static_suppressed_count"] = int(state.get("static_suppressed_count", 0) or 0) + 1
        if raw_issue.get("candidate_source") == "clang_ast_cfg":
            state["clang_prevalidation_decision_count"] = int(
                state.get("clang_prevalidation_decision_count", 0) or 0
            ) + 1

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
        val_agent_cfg = next((a for a in self.config.project.agents if a.name == "validator_agent"), None)
        val_llm_ref = val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
        val_client = self.llm_clients.get(val_llm_ref, self.llm_clients["default"])
        return self.validator_agent_factory(
            val_client,
            self.get_tools("validator_agent"),
            tool_policy=self.tool_policy_for_agent("validator_agent"),
        )

    def _validator_enabled(self) -> bool:
        return any(a.name == "validator_agent" and a.enabled for a in self.config.project.agents)

    def _issue_function(self, raw_issue: Dict[str, Any], state: Dict[str, Any]) -> str:
        agent_context = state.get("agent_context") if isinstance(state.get("agent_context"), dict) else {}
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
        return issue_code

    def _get_function_impl(self, func_name: str) -> Optional[Dict[str, Any]]:
        getter = getattr(self.code_index, "get_function_impl", None)
        if not callable(getter):
            return None
        try:
            return getter(func_name, warn_missing=False)
        except TypeError:
            return getter(func_name)
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
        raw_issue["validation_function_normalization_reason"] = "external_api_function_without_indexed_body"
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
    ) -> Dict[str, Any]:
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
