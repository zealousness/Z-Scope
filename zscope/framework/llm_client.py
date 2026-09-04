"""
Enhanced LLM client with model fallback support.
"""

import ast
from collections import deque
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
import errno
import hashlib
import random
import re
import json
import logging
import os
import ssl
import statistics
import threading
import time
import shutil
import subprocess
import tempfile
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Union,
    cast,
)

import requests

from ..common.cancellation import current_cancellation_token
from ..common.utils import extract_json_blocks
from .conversation_recorder import ConversationSession, get_conversation_recorder
from .llm_usage import (
    LLMUsageAttribution,
    ScanTokenUsageLedger,
    TokenUsageReservation,
)

logger = logging.getLogger(__name__)


@dataclass
class _BaseUrlState:
    url: str
    requests_started: Deque[float] = field(default_factory=deque)
    cooldown_until: float = 0.0


@dataclass
class _EndpointCapacityState:
    url: str
    hard_max_concurrent_requests: int = 0
    max_concurrent_requests: int = 0
    in_flight: int = 0
    rate_limit_per_minute: int = 0
    requests_started: Deque[float] = field(default_factory=deque)
    success_streak: int = 0
    overload_events: int = 0


@dataclass
class _GlobalCapacityState:
    hard_max_concurrent_requests: int = 0
    in_flight: int = 0


@dataclass
class _UsageTelemetryState:
    successful_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_calls: int = 0
    provider_reported_calls: int = 0
    successful_call_durations_seconds: List[float] = field(default_factory=list)


_ENDPOINT_CAPACITY_CONDITION = threading.Condition()
_ENDPOINT_CAPACITY_STATES: Dict[str, _EndpointCapacityState] = {}
_GLOBAL_CAPACITY_STATE = _GlobalCapacityState()


class LLMClient:
    """
    OpenAI-compatible LLM client with model fallback support.
    """

    MODEL_CONTEXT_KEEP_RECENT_TOOL_ROUNDS = 50
    MODEL_CONTEXT_INLINE_OLD_TOOL_CHARS = 900
    MODEL_CONTEXT_TOOL_RESULT_SUMMARY_CHARS = 1800
    MODEL_CONTEXT_SUMMARY_STRING_CHARS = 500
    MODEL_CONTEXT_SUMMARY_HEAVY_STRING_CHARS = 900
    MODEL_CONTEXT_SUMMARY_MAX_ITEMS = 8
    MODEL_CONTEXT_SUMMARY_MAX_KEYS = 18
    LOCAL_FD_EXHAUSTION_COOLDOWN_SECONDS = 2.0
    SESSION_POOL_MAXSIZE = 1
    DEFAULT_GLOBAL_MAX_INFLIGHT = 8
    AIMD_SUCCESS_THRESHOLD = 20
    AIMD_DECREASE_FACTOR = 0.5
    TRANSIENT_AUTH_RETRY_LIMIT = 1
    TRANSIENT_AUTH_RETRY_DELAY_SECONDS = 1.0
    _SUMMARY_PRIORITY_KEYS = (
        "success",
        "error",
        "function_name",
        "func_name",
        "name",
        "file",
        "file_path",
        "filename",
        "location",
        "line",
        "line_range",
        "start_line",
        "end_line",
        "signature",
        "summary",
        "truncated",
        "callee",
        "callees",
        "caller",
        "callers",
        "category",
        "severity",
        "confidence",
        "verdict",
    )
    _SUMMARY_HEAVY_KEYS = {
        "code",
        "text",
        "content",
        "body",
        "source",
        "raw",
        "implementation",
        "conversation",
        "messages",
        "tool_calls",
        "tool_results",
        "data",
    }

    def __init__(
        self,
        api_key: str,
        base_url: Union[str, Sequence[str]],
        models: List[str],
        timeout: Optional[float] = 120.0,
        max_retries: int = 2,
        retry_until_available: bool = False,
        max_tokens: int = 4096,
        base_url_rate_limit_per_minute: Optional[int] = None,
        base_url_max_concurrent_requests: Optional[int] = None,
        global_max_concurrent_requests: int = DEFAULT_GLOBAL_MAX_INFLIGHT,
        supports_structured_output: bool = False,
        token_usage_ledger: Optional[ScanTokenUsageLedger] = None,
        llm_ref: str = "",
    ):
        """
        Initialize LLM client.

        Args:
            api_key: API key
            base_url: API base URL or ordered list of API base URLs
            models: List of model names in order of priority
            timeout: Request timeout in seconds
            max_retries: Retries per model
            retry_until_available: Keep retrying transient transport/provider
                failures after ``max_retries`` until the request succeeds or
                the scan is cancelled.
        """
        self.api_key = api_key
        self.base_urls = self._normalize_base_urls(base_url)
        self.base_url = self.base_urls[0]
        self.models = models
        self.timeout = float(timeout) if timeout is not None else None
        self.max_retries = max_retries
        self.retry_until_available = bool(retry_until_available)
        self.max_tokens = max_tokens
        self.supports_structured_output = bool(supports_structured_output)
        self.token_usage_ledger = token_usage_ledger
        self.llm_ref = str(llm_ref or "")
        self.base_url_rate_limit_per_minute = max(0, int(base_url_rate_limit_per_minute or 0))
        self.base_url_max_concurrent_requests = max(0, int(base_url_max_concurrent_requests or 0))
        configured_global_limit = int(global_max_concurrent_requests or 0)
        self.global_max_concurrent_requests = (
            configured_global_limit
            if configured_global_limit > 0
            else self.DEFAULT_GLOBAL_MAX_INFLIGHT
        )
        self.effective_max_concurrent_requests = self._strictest_positive_limit(
            self.base_url_max_concurrent_requests,
            self.global_max_concurrent_requests,
        )
        self._global_capacity_state = self._shared_global_capacity_state(
            self.global_max_concurrent_requests
        )
        self._session_pool_connections = max(1, len(self.base_urls))
        self._session_pool_maxsize = self.SESSION_POOL_MAXSIZE
        self._base_url_states = [_BaseUrlState(url=url) for url in self.base_urls]
        self._endpoint_capacity_states = {
            url: self._shared_endpoint_capacity_state(
                url,
                self.effective_max_concurrent_requests,
                self.base_url_rate_limit_per_minute,
            )
            for url in self.base_urls
        }
        self._base_url_condition = _ENDPOINT_CAPACITY_CONDITION
        self._last_concurrency_wait_log_at = 0.0
        self._last_rate_wait_log_at = 0.0
        self._session_headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self._transport = os.environ.get("Z_SCOPE_LLM_TRANSPORT", "requests").strip().lower()
        self._curl_bin = os.environ.get("Z_SCOPE_CURL_BIN", "").strip()
        self._thread_local = threading.local()
        self._sessions_lock = threading.Lock()
        self._sessions: Set[requests.Session] = set()
        self._usage_lock = threading.Lock()
        self._usage_telemetry = _UsageTelemetryState()
        self.session = self._new_session()
        self._thread_local.session = self.session

    @staticmethod
    def _strictest_positive_limit(*limits: int) -> int:
        positive = [int(limit) for limit in limits if int(limit or 0) > 0]
        return min(positive) if positive else 0

    @staticmethod
    def _shared_global_capacity_state(
        max_concurrent_requests: int,
    ) -> _GlobalCapacityState:
        with _ENDPOINT_CAPACITY_CONDITION:
            if max_concurrent_requests > 0:
                _GLOBAL_CAPACITY_STATE.hard_max_concurrent_requests = (
                    LLMClient._strictest_positive_limit(
                        _GLOBAL_CAPACITY_STATE.hard_max_concurrent_requests,
                        max_concurrent_requests,
                    )
                )
            return _GLOBAL_CAPACITY_STATE

    @staticmethod
    def _shared_endpoint_capacity_state(
        url: str,
        max_concurrent_requests: int,
        rate_limit_per_minute: int = 0,
    ) -> _EndpointCapacityState:
        with _ENDPOINT_CAPACITY_CONDITION:
            state = _ENDPOINT_CAPACITY_STATES.get(url)
            if state is None:
                state = _EndpointCapacityState(url=url)
                _ENDPOINT_CAPACITY_STATES[url] = state
            if max_concurrent_requests > 0:
                state.hard_max_concurrent_requests = LLMClient._strictest_positive_limit(
                    state.hard_max_concurrent_requests,
                    max_concurrent_requests,
                )
                if state.max_concurrent_requests <= 0:
                    state.max_concurrent_requests = state.hard_max_concurrent_requests
                else:
                    state.max_concurrent_requests = min(
                        state.max_concurrent_requests,
                        state.hard_max_concurrent_requests,
                    )
            if rate_limit_per_minute > 0:
                state.rate_limit_per_minute = LLMClient._strictest_positive_limit(
                    state.rate_limit_per_minute,
                    rate_limit_per_minute,
                )
            return state

    def endpoint_capacity_snapshot(self) -> Dict[str, Dict[str, int]]:
        """Return observable process-wide capacity state for this client's endpoints."""
        with self._base_url_condition:
            return {
                url: {
                    "hard_max_concurrent_requests": state.hard_max_concurrent_requests,
                    "max_concurrent_requests": state.max_concurrent_requests,
                    "in_flight": state.in_flight,
                    "rate_limit_per_minute": state.rate_limit_per_minute,
                    "recent_requests": len(state.requests_started),
                    "overload_events": state.overload_events,
                }
                for url, state in self._endpoint_capacity_states.items()
            }

    def global_capacity_snapshot(self) -> Dict[str, int]:
        """Return the process-wide capacity shared by all configured endpoints."""
        with self._base_url_condition:
            return {
                "hard_max_concurrent_requests": (
                    self._global_capacity_state.hard_max_concurrent_requests
                ),
                "in_flight": self._global_capacity_state.in_flight,
            }

    def usage_snapshot(self) -> Dict[str, Union[int, float]]:
        """Return response-boundary usage that survives caller cancellation.

        Usage is committed as soon as a successful provider response has been
        assembled.  It is deliberately owned by the shared client rather than
        an entry result, so abandoning or replacing that result cannot erase
        tokens already consumed by the scan.
        """
        with self._usage_lock:
            usage = self._usage_telemetry
            successful_calls = usage.successful_calls
            durations = sorted(usage.successful_call_durations_seconds)
            p95_index = max(0, (95 * len(durations) + 99) // 100 - 1) if durations else 0
            duration_total = sum(durations)
            return {
                "successful_calls": successful_calls,
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
                "estimated_calls": usage.estimated_calls,
                "provider_reported_calls": usage.provider_reported_calls,
                "provider_usage_coverage": (
                    usage.provider_reported_calls / successful_calls if successful_calls else 0.0
                ),
                "successful_call_wall_seconds_total": duration_total,
                "successful_call_wall_seconds_mean": (
                    duration_total / len(durations) if durations else 0.0
                ),
                "successful_call_wall_seconds_p50": (
                    statistics.median(durations) if durations else 0.0
                ),
                "successful_call_wall_seconds_p95": (durations[p95_index] if durations else 0.0),
                "successful_call_wall_seconds_max": max(durations, default=0.0),
            }

    @staticmethod
    def _usage_value(value: Any, fallback: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return max(0, int(fallback))
        return max(0, int(value))

    @classmethod
    def _estimate_request_prompt_tokens(
        cls,
        messages: List[Dict[str, Any]],
        *,
        tools: Optional[List[Dict[str, Any]]],
        response_format: Optional[Dict[str, Any]],
    ) -> int:
        """Estimate the complete request prompt before the manager adds its safety margin."""

        estimate = cls.estimate_tokens(messages)
        protocol_payload: Dict[str, Any] = {}
        if tools:
            protocol_payload["tools"] = tools
        if response_format:
            protocol_payload["response_format"] = response_format
        if protocol_payload:
            rendered = json.dumps(protocol_payload, ensure_ascii=False, separators=(",", ":"))
            estimate += int((len(rendered) + 3) / 3.8)
        # Provider chat templates add role and message framing that is absent
        # from the content-only estimator.
        estimate += 8 * max(1, len(messages))
        return max(1, estimate)

    def _reserve_scan_usage(
        self,
        messages: List[Dict[str, Any]],
        *,
        tools: Optional[List[Dict[str, Any]]],
        response_format: Optional[Dict[str, Any]],
        max_completion_tokens: int,
        model: str,
        trace_agent: Optional[str],
        trace_label: Optional[str],
        usage_attribution: Optional[Mapping[str, Any]],
    ) -> Optional[TokenUsageReservation]:
        manager = self.token_usage_ledger
        if manager is None:
            return None
        attribution = LLMUsageAttribution.from_trace(
            trace_agent=trace_agent,
            trace_label=trace_label,
            llm_ref=self.llm_ref,
            explicit=usage_attribution,
        )
        return manager.reserve(
            self._estimate_request_prompt_tokens(
                messages,
                tools=tools,
                response_format=response_format,
            ),
            max_completion_tokens,
            attribution=attribution,
            model=model,
        )

    def _settle_scan_usage(
        self,
        reservation: Optional[TokenUsageReservation],
        usage: Mapping[str, Any],
        *,
        finish_reason: str = "",
        retry: bool = False,
        repair: bool = False,
        tool_call_count: int = 0,
        new_fact_count: int = 0,
        duration_ms: int = 0,
    ) -> Optional[Dict[str, Any]]:
        manager = self.token_usage_ledger
        if manager is None or reservation is None:
            return None
        prompt = self._usage_value(usage.get("prompt_tokens"))
        completion = self._usage_value(usage.get("completion_tokens"))
        total = self._usage_value(usage.get("total_tokens"), prompt + completion)
        event = manager.settle(
            reservation,
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=total,
            provider_reported=not bool(usage.get("estimated", True)),
            finish_reason=finish_reason,
            cached_prompt_tokens=self._usage_value(usage.get("cached_prompt_tokens")),
            reasoning_tokens=self._usage_value(usage.get("reasoning_tokens")),
            retry=retry,
            repair=repair,
            tool_call_count=tool_call_count,
            new_fact_count=new_fact_count,
            duration_ms=duration_ms,
        )
        return event.to_dict()

    @classmethod
    def _normalized_provider_usage(cls, value: Any) -> Dict[str, Any]:
        """Normalize OpenAI-compatible usage variants without retaining content."""

        if not isinstance(value, Mapping):
            return {}

        def first_number(*values: Any) -> Optional[int]:
            for candidate in values:
                if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
                    continue
                return max(0, int(candidate))
            return None

        prompt_details = value.get("prompt_tokens_details")
        if not isinstance(prompt_details, Mapping):
            prompt_details = value.get("input_tokens_details")
        if not isinstance(prompt_details, Mapping):
            prompt_details = {}
        completion_details = value.get("completion_tokens_details")
        if not isinstance(completion_details, Mapping):
            completion_details = value.get("output_tokens_details")
        if not isinstance(completion_details, Mapping):
            completion_details = {}

        prompt = first_number(value.get("prompt_tokens"), value.get("input_tokens"))
        completion = first_number(
            value.get("completion_tokens"),
            value.get("output_tokens"),
        )
        total = first_number(value.get("total_tokens"))
        if prompt is None and completion is None and total is None:
            return {}
        prompt = prompt or 0
        completion = completion or 0
        total = max(prompt + completion, total or 0)
        return {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": total,
            "cached_prompt_tokens": first_number(
                value.get("cached_prompt_tokens"),
                prompt_details.get("cached_tokens"),
            )
            or 0,
            "reasoning_tokens": first_number(
                value.get("reasoning_tokens"),
                completion_details.get("reasoning_tokens"),
            )
            or 0,
            "estimated": False,
        }

    @staticmethod
    def _usage_call_flags(
        *,
        attempt: int,
        trace_label: Optional[str],
        usage_attribution: Optional[Mapping[str, Any]],
    ) -> tuple[bool, bool, int]:
        explicit = usage_attribution or {}
        label = str(trace_label or "").lower()
        call_kind = str(explicit.get("call_kind") or "").lower()
        retry = bool(explicit.get("retry")) or attempt > 1 or "retry" in label
        repair = bool(explicit.get("repair")) or any(
            marker in f"{label} {call_kind}"
            for marker in ("repair", "json_retry", "structured_retry")
        )
        raw_new_facts = explicit.get("new_fact_count", 0)
        if not raw_new_facts:
            match = re.search(r"(?:^|[;\s])new_fact_count\s*=\s*(\d+)", label)
            if match:
                raw_new_facts = int(match.group(1))
        new_fact_count = (
            max(0, int(raw_new_facts))
            if isinstance(raw_new_facts, (int, float)) and not isinstance(raw_new_facts, bool)
            else 0
        )
        return retry, repair, new_fact_count

    def _record_successful_usage(
        self,
        usage: Dict[str, Any],
        *,
        duration_seconds: Optional[float] = None,
    ) -> None:
        def _token_count(value: Any, fallback: int = 0) -> int:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return fallback
            return max(0, int(value))

        prompt_tokens = _token_count(usage.get("prompt_tokens"))
        completion_tokens = _token_count(usage.get("completion_tokens"))
        total_tokens = _token_count(
            usage.get("total_tokens"),
            prompt_tokens + completion_tokens,
        )
        estimated = bool(usage.get("estimated", True))
        with self._usage_lock:
            telemetry = self._usage_telemetry
            telemetry.successful_calls += 1
            telemetry.prompt_tokens += prompt_tokens
            telemetry.completion_tokens += completion_tokens
            telemetry.total_tokens += total_tokens
            if estimated:
                telemetry.estimated_calls += 1
            else:
                telemetry.provider_reported_calls += 1
            if duration_seconds is not None:
                telemetry.successful_call_durations_seconds.append(
                    max(0.0, float(duration_seconds))
                )

    def _has_successful_call(self) -> bool:
        """Return whether this configured client has already authenticated successfully."""

        with self._usage_lock:
            return self._usage_telemetry.successful_calls > 0

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update(self._session_headers)
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self._session_pool_connections,
            pool_maxsize=self._session_pool_maxsize,
            max_retries=0,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        with self._sessions_lock:
            self._sessions.add(session)
        return session

    def _session_for_thread(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = self._new_session()
            self._thread_local.session = session
        return cast(requests.Session, session)

    def close_thread_session(self) -> None:
        """Close this client's HTTP session for the current thread."""
        session = getattr(self._thread_local, "session", None)
        if session is None:
            return
        try:
            session.close()
        finally:
            with self._sessions_lock:
                self._sessions.discard(session)
            try:
                delattr(self._thread_local, "session")
            except AttributeError:
                pass

    def close(self) -> None:
        """Close all HTTP sessions known to this client."""
        with self._sessions_lock:
            sessions = list(self._sessions)
            self._sessions.clear()
        for session in sessions:
            try:
                session.close()
            except Exception:
                logger.debug("Failed to close LLM HTTP session", exc_info=True)
        try:
            delattr(self._thread_local, "session")
        except AttributeError:
            pass

    @staticmethod
    def _normalize_base_urls(base_url: Union[str, Sequence[str]]) -> List[str]:
        if isinstance(base_url, str):
            candidates: Sequence[Any] = [base_url]
        else:
            candidates = base_url

        urls: List[str] = []
        for candidate in candidates:
            cleaned = str(candidate).strip().rstrip("/")
            if cleaned and cleaned not in urls:
                urls.append(cleaned)
        if not urls:
            raise ValueError("At least one LLM base_url must be configured.")
        return urls

    @staticmethod
    def _chat_completion_url(base_url: str) -> str:
        if "/chat/completions" in base_url:
            return base_url
        return f"{base_url}/chat/completions"

    def _select_base_url(self) -> _BaseUrlState:
        while True:
            token = current_cancellation_token()
            if token is not None:
                token.raise_if_cancelled()
            now = time.monotonic()
            with self._base_url_condition:
                for state in self._base_url_states:
                    self._prune_recent_requests(state, now)
                    self._prune_endpoint_requests(
                        self._endpoint_capacity_states[state.url],
                        now,
                    )

                has_global_capacity = self._has_global_concurrent_capacity()
                candidates = [
                    state
                    for state in self._base_url_states
                    if (
                        has_global_capacity
                        and state.cooldown_until <= now
                        and self._has_minute_capacity(self._endpoint_capacity_states[state.url])
                        and self._has_concurrent_capacity(self._endpoint_capacity_states[state.url])
                    )
                ]
                if candidates:
                    selected = min(
                        candidates,
                        key=lambda state: (
                            len(self._endpoint_capacity_states[state.url].requests_started),
                            self._endpoint_capacity_states[state.url].in_flight,
                            len(state.requests_started),
                        ),
                    )
                    selected.requests_started.append(now)
                    endpoint = self._endpoint_capacity_states[selected.url]
                    endpoint.requests_started.append(now)
                    endpoint.in_flight += 1
                    self._global_capacity_state.in_flight += 1
                    return selected

                blocked_by_concurrency_only = (
                    not has_global_capacity
                    and any(
                        state.cooldown_until <= now
                        and self._has_minute_capacity(self._endpoint_capacity_states[state.url])
                        for state in self._base_url_states
                    )
                ) or any(
                    state.cooldown_until <= now
                    and self._has_minute_capacity(self._endpoint_capacity_states[state.url])
                    and not self._has_concurrent_capacity(self._endpoint_capacity_states[state.url])
                    for state in self._base_url_states
                )
                wait_until = min(
                    self._next_available_at(state, now) for state in self._base_url_states
                )

                wait_time = max(0.05, min(wait_until - now, 10.0))
                if token is not None:
                    remaining = token.remaining_seconds()
                    if remaining is not None:
                        wait_time = min(wait_time, max(0.01, remaining))
                self._log_base_url_wait(blocked_by_concurrency_only, wait_time, now)
                self._base_url_condition.wait(timeout=wait_time)

    def _release_base_url(self, state: _BaseUrlState) -> None:
        with self._base_url_condition:
            endpoint = self._endpoint_capacity_states.get(state.url)
            if endpoint is not None:
                endpoint.in_flight = max(0, endpoint.in_flight - 1)
            self._global_capacity_state.in_flight = max(
                0,
                self._global_capacity_state.in_flight - 1,
            )
            self._base_url_condition.notify_all()

    def _mark_base_url_cooldown(self, state: _BaseUrlState, seconds: float) -> None:
        if seconds <= 0:
            return
        until = time.monotonic() + seconds
        with self._base_url_condition:
            state.cooldown_until = max(state.cooldown_until, until)
            self._base_url_condition.notify_all()

    def _mark_all_base_urls_cooldown(self, seconds: float) -> None:
        if seconds <= 0:
            return
        until = time.monotonic() + seconds
        with self._base_url_condition:
            for state in self._base_url_states:
                state.cooldown_until = max(state.cooldown_until, until)
            self._base_url_condition.notify_all()

    def _log_base_url_wait(
        self,
        blocked_by_concurrency_only: bool,
        wait_time: float,
        now: float,
    ) -> None:
        if blocked_by_concurrency_only:
            if now - self._last_concurrency_wait_log_at < 5.0:
                return
            self._last_concurrency_wait_log_at = now
            logger.debug(
                "All LLM base_urls are at configured concurrency capacity; waiting %.1fs...",
                wait_time,
            )
            return

        if now - self._last_rate_wait_log_at < 5.0:
            return
        self._last_rate_wait_log_at = now
        logger.warning(
            "All LLM base_urls are at rate capacity or cooling down; waiting %.1fs...",
            wait_time,
        )

    def _prune_recent_requests(self, state: _BaseUrlState, now: float) -> None:
        while state.requests_started and now - state.requests_started[0] >= 60.0:
            state.requests_started.popleft()

    @staticmethod
    def _prune_endpoint_requests(
        state: _EndpointCapacityState,
        now: float,
    ) -> None:
        while state.requests_started and now - state.requests_started[0] >= 60.0:
            state.requests_started.popleft()

    @staticmethod
    def _has_minute_capacity(state: _EndpointCapacityState) -> bool:
        if state.rate_limit_per_minute <= 0:
            return True
        return len(state.requests_started) < state.rate_limit_per_minute

    def _has_concurrent_capacity(self, state: _EndpointCapacityState) -> bool:
        if state.max_concurrent_requests <= 0:
            return True
        return state.in_flight < state.max_concurrent_requests

    def _has_global_concurrent_capacity(self) -> bool:
        hard_limit = self._global_capacity_state.hard_max_concurrent_requests
        if hard_limit <= 0:
            return True
        return self._global_capacity_state.in_flight < hard_limit

    def _next_available_at(self, state: _BaseUrlState, now: float) -> float:
        endpoint = self._endpoint_capacity_states[state.url]
        available_at = max(state.cooldown_until, now)
        if (
            endpoint.rate_limit_per_minute > 0
            and len(endpoint.requests_started) >= endpoint.rate_limit_per_minute
        ):
            available_at = max(available_at, endpoint.requests_started[0] + 60.0)
        if not self._has_concurrent_capacity(endpoint):
            available_at = max(available_at, now + 0.5)
        if not self._has_global_concurrent_capacity():
            available_at = max(available_at, now + 0.5)
        return available_at

    def _record_endpoint_success(self, state: _BaseUrlState) -> None:
        endpoint = self._endpoint_capacity_states[state.url]
        with self._base_url_condition:
            hard_limit = endpoint.hard_max_concurrent_requests
            if hard_limit <= 0 or endpoint.max_concurrent_requests >= hard_limit:
                endpoint.success_streak = 0
                return
            endpoint.success_streak += 1
            if endpoint.success_streak < self.AIMD_SUCCESS_THRESHOLD:
                return
            endpoint.max_concurrent_requests = min(
                hard_limit,
                endpoint.max_concurrent_requests + 1,
            )
            endpoint.success_streak = 0
            self._base_url_condition.notify_all()
            logger.info(
                "LLM endpoint %s AIMD increased concurrency to %d/%d",
                state.url,
                endpoint.max_concurrent_requests,
                hard_limit,
            )

    def _record_endpoint_overload(
        self,
        state: _BaseUrlState,
        *,
        reason: str,
    ) -> None:
        endpoint = self._endpoint_capacity_states[state.url]
        with self._base_url_condition:
            current_limit = (
                endpoint.max_concurrent_requests or endpoint.hard_max_concurrent_requests
            )
            if current_limit <= 1:
                endpoint.success_streak = 0
                endpoint.overload_events += 1
                return
            reduced_limit = max(
                2,
                int(current_limit * self.AIMD_DECREASE_FACTOR),
            )
            endpoint.max_concurrent_requests = min(current_limit, reduced_limit)
            endpoint.success_streak = 0
            endpoint.overload_events += 1
            self._base_url_condition.notify_all()
            if endpoint.max_concurrent_requests < current_limit:
                logger.warning(
                    "LLM endpoint %s AIMD reduced concurrency from %d to %d (%s)",
                    state.url,
                    current_limit,
                    endpoint.max_concurrent_requests,
                    reason,
                )
            else:
                logger.debug(
                    "LLM endpoint %s remains at AIMD concurrency floor %d (%s)",
                    state.url,
                    endpoint.max_concurrent_requests,
                    reason,
                )

    @staticmethod
    def _retry_after_seconds(response: requests.Response) -> Optional[float]:
        retry_after = response.headers.get("Retry-After")
        if not retry_after:
            return None
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
        try:
            retry_at = parsedate_to_datetime(retry_after)
            return max(0.0, retry_at.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None

    @classmethod
    def _is_too_many_open_files(cls, error: BaseException) -> bool:
        pending: List[Any] = [error]
        seen: set[int] = set()
        while pending:
            current = pending.pop()
            if current is None:
                continue
            current_id = id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            if isinstance(current, OSError) and current.errno == errno.EMFILE:
                return True
            if getattr(current, "errno", None) == errno.EMFILE:
                return True
            text = str(current)
            if "[Errno 24]" in text or "Too many open files" in text:
                return True
            if isinstance(current, BaseException):
                pending.append(current.__cause__)
                pending.append(current.__context__)
                pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        return False

    @classmethod
    def _endpoint_overload_reason(cls, error: BaseException) -> Optional[str]:
        """Classify transient endpoint failures that require AIMD load shedding."""
        pending: List[Any] = [error]
        seen: set[int] = set()
        while pending:
            current = pending.pop()
            if current is None:
                continue
            current_id = id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            if isinstance(current, (requests.exceptions.Timeout, TimeoutError)):
                return "timeout"
            if isinstance(current, (requests.exceptions.SSLError, ssl.SSLError)):
                return "ssl_error"
            if isinstance(
                current,
                (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ChunkedEncodingError,
                    ConnectionError,
                ),
            ):
                return "connection_error"
            if isinstance(current, BaseException):
                pending.append(current.__cause__)
                pending.append(current.__context__)
                pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        return None

    def _recover_from_local_fd_exhaustion(
        self,
        error: BaseException,
        cooldown_seconds: float,
    ) -> None:
        logger.warning(
            "Local file descriptor exhaustion while calling LLM; closing current "
            "thread HTTP session and cooling all base_urls for %.1fs: %s",
            cooldown_seconds,
            error,
        )
        self.close_thread_session()
        self._mark_all_base_urls_cooldown(cooldown_seconds)

    # ------------------------------------------------------------------
    # Conversation recording helpers. Every helper is a no-op unless the
    # process-wide recorder is enabled (verbose runs) and a trace session
    # exists, so instrumented call sites carry no overhead otherwise.
    # ------------------------------------------------------------------

    @staticmethod
    def _tools_schema_hash(tools_schema: Optional[List[Dict[str, Any]]]) -> Optional[str]:
        if not tools_schema:
            return None
        try:
            canonical = json.dumps(tools_schema, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            canonical = repr(tools_schema)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _record_chat_exchange(
        recorder: Any,
        trace_session: Optional[ConversationSession],
        created_trace_session: bool,
        *,
        iteration: Optional[int],
        messages: List[Dict[str, Any]],
        assembled_message: Dict[str, Any],
        finish_reason: Optional[str],
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        duration_ms: int,
        attempt_count: int,
        base_url: str,
        usage_event: Optional[Mapping[str, Any]] = None,
        usage_attribution: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not (recorder and trace_session):
            return
        usage_event_id = None
        if isinstance(usage_event, Mapping):
            usage_event_id = usage_event.get("sequence")
        recorder.record_exchange(
            trace_session,
            iteration,
            messages,
            assembled_message,
            finish_reason,
            model,
            prompt_tokens,
            completion_tokens,
            duration_ms=duration_ms,
            attempt_count=attempt_count,
            base_url=base_url,
            usage_event_id=usage_event_id,
            attribution=dict(usage_attribution) if usage_attribution else None,
        )
        if created_trace_session:
            recorder.record_session_end(
                trace_session,
                iteration or 1,
                prompt_tokens + completion_tokens,
                truncated=finish_reason == "length",
                cumulative_prompt_tokens=prompt_tokens,
                cumulative_completion_tokens=completion_tokens,
                cumulative_total_tokens=prompt_tokens + completion_tokens,
                finish_reason=finish_reason,
            )

    @staticmethod
    def _record_attempt_failure(
        trace_session: Optional[ConversationSession],
        iteration: Optional[int],
        *,
        model: Optional[str],
        base_url: Optional[str],
        attempt: Optional[int],
        outcome: str,
        error: Optional[str] = None,
        delay_ms: Optional[int] = None,
    ) -> None:
        recorder = get_conversation_recorder()
        if recorder is None or trace_session is None:
            return
        recorder.record_attempt_failure(
            trace_session,
            iteration,
            model=model,
            base_url=base_url,
            attempt=attempt,
            outcome=outcome,
            error=error,
            delay_ms=delay_ms,
        )

    @staticmethod
    def _attempt_failure_outcome(error: BaseException) -> str:
        if isinstance(error, requests.exceptions.Timeout):
            return "timeout"
        if isinstance(error, requests.exceptions.SSLError):
            return "tls_error"
        if isinstance(error, requests.exceptions.ConnectionError):
            return "connect_error"
        return "request_error"

    @staticmethod
    def _record_control_event(
        trace_session: Optional[ConversationSession],
        iteration: int,
        kind: str,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> None:
        recorder = get_conversation_recorder()
        if recorder is None or trace_session is None:
            return
        recorder.record_iteration_control(
            trace_session,
            iteration,
            kind,
            dict(detail) if detail else None,
        )

    @staticmethod
    def _record_loop_guard_event(
        trace_session: Optional[ConversationSession],
        iteration: int,
        **fields: Any,
    ) -> None:
        recorder = get_conversation_recorder()
        if recorder is None or trace_session is None:
            return
        recorder.record_loop_guard(trace_session, iteration, **fields)

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        response_format: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        trace_agent: Optional[str] = None,
        trace_label: Optional[str] = None,
        trace_iteration: Optional[int] = None,
        trace_session: Optional[ConversationSession] = None,
        usage_attribution: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send chat completion request with model fallback.
        """
        token = current_cancellation_token()
        if token is not None:
            token.raise_if_cancelled()
        last_error = None
        recorder = get_conversation_recorder()
        created_trace_session = False
        if recorder and trace_session is None:
            trace_session = recorder.begin_session(
                trace_agent or "direct_chat",
                trace_label,
                tools_schema_hash=self._tools_schema_hash(tools),
            )
            created_trace_session = True

        for model in self.models:
            logger.info(f"Using model: {model}")

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens or self.max_tokens,
            }

            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = tool_choice if tool_choice is not None else "auto"
            if response_format:
                payload["response_format"] = response_format

            # Force streaming to bypass middle-proxy timeouts (e.g. 504 on 120s limit)
            payload["stream"] = True
            # OpenAI-compatible streaming APIs only include the terminal usage
            # chunk when explicitly requested.  Provider-reported usage is a
            # formal benchmark invariant; incompatible endpoints remain
            # visible as estimated telemetry instead of being misclassified.
            payload["stream_options"] = {"include_usage": True}

            total_attempts = (self.max_retries + 1) * max(1, len(self._base_url_states))
            attempt = 0
            retry_transient = False
            retry_transient_auth = False
            transient_auth_retries_remaining = self.TRANSIENT_AUTH_RETRY_LIMIT
            while (
                attempt < total_attempts
                or (self.retry_until_available and retry_transient)
                or retry_transient_auth
            ):
                retry_transient = False
                retry_transient_auth = False
                attempt += 1
                token = current_cancellation_token()
                if token is not None:
                    token.raise_if_cancelled()
                endpoint = self._select_base_url()
                post_attempt_delay = 0.0
                response: Optional[requests.Response] = None
                usage_reservation: Optional[TokenUsageReservation] = None
                usage_settled = False
                request_started: Optional[float] = None
                retry_call, repair_call, new_fact_count = self._usage_call_flags(
                    attempt=attempt,
                    trace_label=trace_label,
                    usage_attribution=usage_attribution,
                )
                try:
                    url = self._chat_completion_url(endpoint.url)
                    requested_max_tokens = self._usage_value(
                        payload.get("max_tokens"),
                        self.max_tokens,
                    )
                    usage_reservation = self._reserve_scan_usage(
                        messages,
                        tools=tools,
                        response_format=response_format,
                        max_completion_tokens=requested_max_tokens,
                        model=model,
                        trace_agent=trace_agent,
                        trace_label=trace_label,
                        usage_attribution=usage_attribution,
                    )
                    attempt_payload = dict(payload)
                    if usage_reservation is not None:
                        attempt_payload["max_tokens"] = usage_reservation.completion_token_limit

                    if self._transport == "curl":
                        request_started = time.monotonic()
                        assembled_message, finish_reason, provider_usage = (
                            self._curl_chat_completion(
                                url,
                                attempt_payload,
                            )
                        )
                        prompt_tokens = LLMClient.estimate_tokens(messages)
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        usage: Dict[str, Any] = {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                            "estimated": True,
                        }
                        normalized_provider_usage = self._normalized_provider_usage(provider_usage)
                        if normalized_provider_usage:
                            usage.update(normalized_provider_usage)
                        duration_seconds = time.monotonic() - request_started
                        self._record_successful_usage(
                            usage,
                            duration_seconds=duration_seconds,
                        )
                        tool_calls = assembled_message.get("tool_calls")
                        tool_call_count = len(tool_calls) if isinstance(tool_calls, list) else 0
                        usage_event = self._settle_scan_usage(
                            usage_reservation,
                            usage,
                            finish_reason=finish_reason,
                            retry=retry_call,
                            repair=repair_call,
                            tool_call_count=tool_call_count,
                            new_fact_count=new_fact_count,
                            duration_ms=max(0, int(round(duration_seconds * 1000))),
                        )
                        usage_settled = usage_reservation is not None
                        if usage_event is not None:
                            usage["usage_event"] = usage_event
                        logger.info(
                            f"[LLM API Trace] Model: {model} | "
                            f"Prompt ~{prompt_tokens:,} tk | "
                            f"Completion ~{completion_tokens:,} tk | "
                            f"Total ~{prompt_tokens + completion_tokens:,} tk"
                        )
                        self._record_chat_exchange(
                            recorder,
                            trace_session,
                            created_trace_session,
                            iteration=trace_iteration,
                            messages=messages,
                            assembled_message=assembled_message,
                            finish_reason=finish_reason,
                            model=model,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            duration_ms=max(0, int(round(duration_seconds * 1000))),
                            attempt_count=attempt,
                            base_url=endpoint.url,
                            usage_event=usage_event,
                            usage_attribution=usage_attribution,
                        )
                        self._record_endpoint_success(endpoint)
                        return {
                            "choices": [
                                {
                                    "message": assembled_message,
                                    "finish_reason": finish_reason,
                                }
                            ],
                            "model": model,
                            "usage": usage,
                        }

                    request_timeout = self.timeout
                    if token is not None:
                        remaining = token.remaining_seconds()
                        if remaining is not None:
                            request_timeout = (
                                max(0.1, remaining)
                                if request_timeout is None
                                else max(0.1, min(request_timeout, remaining))
                            )
                    request_started = time.monotonic()
                    response = self._session_for_thread().post(
                        url, json=attempt_payload, timeout=request_timeout, stream=True
                    )

                    if response.status_code == 200:
                        assembled_message, finish_reason, provider_usage = (
                            self._assemble_chat_response_with_usage(response)
                        )

                        # Estimate single API call cost and log prominently
                        prompt_tokens = LLMClient.estimate_tokens(messages)
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        usage = {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                            "estimated": True,
                        }
                        normalized_provider_usage = self._normalized_provider_usage(provider_usage)
                        if normalized_provider_usage:
                            usage.update(normalized_provider_usage)
                        duration_seconds = time.monotonic() - request_started
                        self._record_successful_usage(
                            usage,
                            duration_seconds=duration_seconds,
                        )
                        tool_calls = assembled_message.get("tool_calls")
                        tool_call_count = len(tool_calls) if isinstance(tool_calls, list) else 0
                        usage_event = self._settle_scan_usage(
                            usage_reservation,
                            usage,
                            finish_reason=finish_reason,
                            retry=retry_call,
                            repair=repair_call,
                            tool_call_count=tool_call_count,
                            new_fact_count=new_fact_count,
                            duration_ms=max(0, int(round(duration_seconds * 1000))),
                        )
                        usage_settled = usage_reservation is not None
                        if usage_event is not None:
                            usage["usage_event"] = usage_event

                        logger.info(
                            f"[LLM API Trace] Model: {model} | "
                            f"Prompt ≈ {prompt_tokens:,} tk | "
                            f"Completion ≈ {completion_tokens:,} tk | "
                            f"Total ≈ {prompt_tokens + completion_tokens:,} tk"
                        )
                        self._record_chat_exchange(
                            recorder,
                            trace_session,
                            created_trace_session,
                            iteration=trace_iteration,
                            messages=messages,
                            assembled_message=assembled_message,
                            finish_reason=finish_reason,
                            model=model,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            duration_ms=max(0, int(round(duration_seconds * 1000))),
                            attempt_count=attempt,
                            base_url=endpoint.url,
                            usage_event=usage_event,
                            usage_attribution=usage_attribution,
                        )

                        self._record_endpoint_success(endpoint)
                        return {
                            "choices": [
                                {"message": assembled_message, "finish_reason": finish_reason}
                            ],
                            "model": model,
                            "usage": usage,
                        }

                    error_msg = f"HTTP {response.status_code}: {response.text}"
                    transient_http_error = (
                        response.status_code >= 500 or response.status_code == 429
                    )
                    logger.warning(
                        "Model %s via %s failed (attempt %d/%s): %s",
                        model,
                        endpoint.url,
                        attempt,
                        (
                            "unbounded"
                            if (self.retry_until_available and transient_http_error)
                            else str(total_attempts)
                        ),
                        error_msg,
                    )

                    if transient_http_error:
                        retry_transient = True
                        if response.status_code in {429, 502, 503, 504}:
                            self._record_endpoint_overload(
                                endpoint,
                                reason=f"http_{response.status_code}",
                            )
                        retry_after = self._retry_after_seconds(response)
                        wait_time = retry_after or min(
                            2 ** min(attempt - 1, 4),
                            10,
                        ) + random.uniform(0, 3)
                        self._mark_base_url_cooldown(endpoint, wait_time)
                        self._record_attempt_failure(
                            trace_session,
                            trace_iteration,
                            model=model,
                            base_url=endpoint.url,
                            attempt=attempt,
                            outcome="rate_limited" if response.status_code == 429 else "http_5xx",
                            error=error_msg,
                            delay_ms=int(wait_time * 1000),
                        )
                        logger.warning(
                            "Rate limited or server error on %s; cooling it down for %.1fs...",
                            endpoint.url,
                            wait_time,
                        )
                        last_error = error_msg
                        continue
                    elif (
                        response.status_code == 401
                        and transient_auth_retries_remaining > 0
                        and self._has_successful_call()
                    ):
                        # A provider can occasionally return an isolated 401 while
                        # concurrent requests using the same credential continue to
                        # succeed. Retry that condition once, but never turn a bad
                        # credential into an unbounded retry loop.
                        transient_auth_retries_remaining -= 1
                        retry_transient_auth = True
                        wait_time = self.TRANSIENT_AUTH_RETRY_DELAY_SECONDS
                        self._mark_base_url_cooldown(endpoint, wait_time)
                        post_attempt_delay = wait_time
                        last_error = error_msg
                        self._record_attempt_failure(
                            trace_session,
                            trace_iteration,
                            model=model,
                            base_url=endpoint.url,
                            attempt=attempt,
                            outcome="auth_retry",
                            error=error_msg,
                            delay_ms=int(wait_time * 1000),
                        )
                        logger.warning(
                            "Endpoint %s returned an isolated HTTP 401 after prior "
                            "successful authentication; retrying once after %.1fs",
                            endpoint.url,
                            wait_time,
                        )
                        continue
                    else:
                        self._record_attempt_failure(
                            trace_session,
                            trace_iteration,
                            model=model,
                            base_url=endpoint.url,
                            attempt=attempt,
                            outcome=f"http_{response.status_code}",
                            error=error_msg,
                        )
                        last_error = error_msg
                        break  # Try next model

                except Exception as e:
                    local_fd_exhausted = self._is_too_many_open_files(e)
                    overload_reason = (
                        None if local_fd_exhausted else self._endpoint_overload_reason(e)
                    )
                    retry_transient = local_fd_exhausted or overload_reason is not None
                    wait_time = min(
                        2 ** min(attempt - 1, 4),
                        10,
                    ) + random.uniform(0, 3)
                    self._record_attempt_failure(
                        trace_session,
                        trace_iteration,
                        model=model,
                        base_url=endpoint.url,
                        attempt=attempt,
                        outcome=self._attempt_failure_outcome(e),
                        error=str(e),
                        delay_ms=int(wait_time * 1000),
                    )
                    if overload_reason is not None:
                        self._record_endpoint_overload(
                            endpoint,
                            reason=overload_reason,
                        )
                        self._mark_base_url_cooldown(endpoint, wait_time)
                    if local_fd_exhausted:
                        wait_time = max(wait_time, self.LOCAL_FD_EXHAUSTION_COOLDOWN_SECONDS)
                        self._recover_from_local_fd_exhaustion(e, wait_time)
                    is_last = attempt >= total_attempts and not (
                        self.retry_until_available and retry_transient
                    )
                    post_attempt_delay = 0.0 if is_last else wait_time
                    if is_last:
                        logger.warning(
                            "Model %s via %s request error (attempt %d/%d, final): %s",
                            model,
                            endpoint.url,
                            attempt,
                            total_attempts,
                            e,
                        )
                    else:
                        logger.warning(
                            "Model %s via %s request error "
                            "(attempt %d/%s, retrying after %.1fs): %s",
                            model,
                            endpoint.url,
                            attempt,
                            (
                                "unbounded"
                                if (
                                    self.retry_until_available
                                    and retry_transient
                                    and attempt >= total_attempts
                                )
                                else str(total_attempts)
                            ),
                            wait_time,
                            e,
                        )
                    last_error = str(e)
                    continue
                finally:
                    if usage_reservation is not None and not usage_settled:
                        try:
                            manager = self.token_usage_ledger
                            if manager is None:
                                raise ValueError("scan token usage ledger is unavailable")
                            duration_ms = (
                                max(0, int(round((time.monotonic() - request_started) * 1000)))
                                if request_started is not None
                                else 0
                            )
                            manager.forfeit(
                                usage_reservation,
                                reason=(str(last_error or "provider_request_failed")[:500]),
                                retry=retry_call,
                                repair=repair_call,
                                duration_ms=duration_ms,
                            )
                        except ValueError:
                            # A successful response can be settled immediately
                            # before a downstream recorder/logging failure.
                            pass
                    if response is not None:
                        close_response = getattr(response, "close", None)
                        if callable(close_response):
                            close_response()
                    self._release_base_url(endpoint)
                    if post_attempt_delay > 0:
                        token = current_cancellation_token()
                        if token is None:
                            time.sleep(post_attempt_delay)
                        elif token.wait(post_attempt_delay):
                            token.raise_if_cancelled()

            self._record_attempt_failure(
                trace_session,
                trace_iteration,
                model=model,
                base_url=None,
                attempt=attempt,
                outcome="model_fallback",
                error=last_error,
            )
            logger.info(f"Falling back from model {model}...")

        raise Exception(f"All models failed. Last error: {last_error}")

    def _curl_chat_completion(
        self,
        url: str,
        payload: Dict[str, Any],
    ) -> tuple[Dict[str, Any], str, Dict[str, Any]]:
        """Send a chat completion request through curl.

        This is intentionally opt-in via ``Z_SCOPE_LLM_TRANSPORT=curl``. It is
        useful on Windows/WSL setups where Python's OpenSSL stack cannot reach a
        provider but the system curl/SChannel path can.
        """

        curl_bin = self._curl_executable()
        curl_payload = dict(payload)
        curl_payload["stream"] = False
        curl_payload.pop("stream_options", None)
        request_bytes = json.dumps(curl_payload, ensure_ascii=False).encode("utf-8")
        status_marker = "\n__Z_SCOPE_HTTP_STATUS__:"
        timeout_seconds = max(float(self.timeout) * 3.0, 60.0) if self.timeout is not None else None
        token = current_cancellation_token()
        if token is not None:
            token.raise_if_cancelled()
            remaining = token.remaining_seconds()
            if remaining is not None:
                timeout_seconds = (
                    max(1.0, remaining)
                    if timeout_seconds is None
                    else max(1.0, min(timeout_seconds, remaining))
                )
        config_path = self._write_curl_config(
            url=url,
            timeout_seconds=timeout_seconds,
            status_marker=status_marker,
        )
        command_config_path = self._curl_command_path(config_path, curl_bin)
        command = [curl_bin, "--config", command_config_path]
        try:
            proc = subprocess.run(
                command,
                input=request_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        finally:
            try:
                os.unlink(config_path)
            except OSError:
                logger.debug("Failed to remove temporary curl config", exc_info=True)
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        if status_marker not in stdout:
            detail = stderr or stdout[-500:] or f"curl exited with {proc.returncode}"
            raise RuntimeError(f"curl transport did not return an HTTP status: {detail}")
        body, raw_status = stdout.rsplit(status_marker, 1)
        try:
            status = int(raw_status.strip()[-3:])
        except ValueError as exc:
            raise RuntimeError(
                f"curl transport returned invalid HTTP status: {raw_status!r}"
            ) from exc
        if proc.returncode != 0:
            detail = stderr or body[-500:] or f"curl exited with {proc.returncode}"
            raise RuntimeError(f"curl transport failed: {detail}")
        if status != 200:
            raise RuntimeError(f"HTTP {status}: {body[:2000]}")
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"curl transport returned non-JSON response: {body[:1000]}") from exc
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError(f"curl transport response missing choices: {body[:1000]}")
        choice = choices[0] if isinstance(choices[0], dict) else {}
        message = choice.get("message") or {}
        if not isinstance(message, dict):
            message = {"role": "assistant", "content": str(message)}
        message.setdefault("role", "assistant")
        message.setdefault("content", "")
        finish_reason = str(choice.get("finish_reason") or "stop")
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return message, finish_reason, dict(usage)

    def _write_curl_config(
        self,
        *,
        url: str,
        timeout_seconds: Optional[float],
        status_marker: str,
    ) -> str:
        fd, path = tempfile.mkstemp(prefix="zscope-curl-", suffix=".cfg")
        auth_header = f"Authorization: {self._session_headers['Authorization']}"
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("silent\n")
            handle.write("show-error\n")
            handle.write("http1.1\n")
            handle.write('request = "POST"\n')
            handle.write(f"url = {self._curl_config_quote(url)}\n")
            handle.write(f"header = {self._curl_config_quote(auth_header)}\n")
            handle.write('header = "Content-Type: application/json"\n')
            handle.write('data-binary = "@-"\n')
            if timeout_seconds is not None:
                handle.write(f'max-time = "{int(timeout_seconds)}"\n')
            handle.write(f"write-out = {self._curl_config_quote(status_marker + '%{http_code}')}\n")
        return path

    @staticmethod
    def _curl_config_quote(value: str) -> str:
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("\t", "\\t")
        )
        return f'"{escaped}"'

    @staticmethod
    def _curl_command_path(path: str, curl_bin: str) -> str:
        if os.name != "posix" or not curl_bin.lower().endswith(".exe"):
            return path
        try:
            converted = subprocess.run(
                ["wslpath", "-w", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError:
            return path
        if converted.returncode != 0:
            return path
        windows_path = converted.stdout.decode("utf-8", errors="replace").strip()
        return windows_path or path

    def _curl_executable(self) -> str:
        if self._curl_bin:
            return self._curl_bin
        for candidate in ("curl.exe", "curl"):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        raise RuntimeError(
            "Z_SCOPE_LLM_TRANSPORT=curl was requested, but no curl executable was found. "
            "Set Z_SCOPE_CURL_BIN to an explicit curl path."
        )

    def _assemble_chat_response(self, response: requests.Response) -> tuple[Dict[str, Any], str]:
        """Assemble either SSE chunks or a plain JSON chat completion response."""
        message, finish_reason, _usage = self._assemble_chat_response_with_usage(response)
        return message, finish_reason

    def _assemble_chat_response_with_usage(
        self,
        response: requests.Response,
    ) -> tuple[Dict[str, Any], str, Dict[str, Any]]:
        """Assemble a response and retain only provider token-accounting fields."""

        content_pieces: List[str] = []
        reasoning_pieces: List[str] = []
        tool_calls_map: Dict[Any, Dict[str, Any]] = {}
        finish_reason = "stop"
        provider_usage: Dict[str, Any] = {}

        # A stream that continues to yield valid provider chunks is healthy.
        # Do not turn request elapsed time into a local analysis budget; the
        # HTTP read timeout and idle-valid-chunk guard still detect a stalled
        # or unavailable service.
        stream_deadline = None
        for chunk in self._iter_chat_chunks(
            response,
            max_stream_seconds=stream_deadline,
            max_idle_valid_chunk_seconds=self.timeout,
        ):
            chunk_usage = chunk.get("usage")
            if isinstance(chunk_usage, dict):
                provider_usage.update(chunk_usage)
            choices = chunk.get("choices", [])
            if not choices:
                continue

            choice = choices[0]
            message_delta = choice.get("delta")
            if not isinstance(message_delta, dict) or not message_delta:
                message_delta = choice.get("message", {})
            if not isinstance(message_delta, dict):
                message_delta = {}

            content = message_delta.get("content")
            if content:
                content_pieces.append(str(content))

            reasoning = message_delta.get("reasoning_content") or message_delta.get("reasoning")
            if reasoning:
                reasoning_pieces.append(str(reasoning))

            tool_calls = message_delta.get("tool_calls") or []
            if isinstance(tool_calls, list):
                for fallback_index, tool_call in enumerate(tool_calls):
                    if isinstance(tool_call, dict):
                        self._merge_tool_call(tool_calls_map, tool_call, fallback_index)

            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]

        assembled_message: Dict[str, Any] = {"role": "assistant"}
        if content_pieces:
            assembled_message["content"] = "".join(content_pieces)
        if tool_calls_map:
            assembled_message["tool_calls"] = [
                tool_calls_map[key] for key in sorted(tool_calls_map.keys(), key=str)
            ]
            assembled_message.setdefault("content", "")
        else:
            assembled_message.setdefault("content", "")
        if reasoning_pieces:
            assembled_message["reasoning_content"] = "".join(reasoning_pieces)

        return assembled_message, finish_reason, provider_usage

    @staticmethod
    def _iter_chat_chunks(
        response: requests.Response,
        *,
        max_stream_seconds: Optional[float] = None,
        max_idle_valid_chunk_seconds: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        stream_started_at = time.monotonic()
        last_valid_chunk_at = stream_started_at
        for line in response.iter_lines():
            token = current_cancellation_token()
            if token is not None:
                token.raise_if_cancelled()
            now = time.monotonic()
            if max_stream_seconds is not None and now - stream_started_at > max_stream_seconds:
                raise TimeoutError(f"Chat completion stream exceeded {max_stream_seconds:.0f}s")

            if not line:
                if (
                    max_idle_valid_chunk_seconds is not None
                    and now - last_valid_chunk_at > max_idle_valid_chunk_seconds
                ):
                    raise TimeoutError(
                        "Chat completion stream did not yield a valid JSON chunk "
                        f"for {max_idle_valid_chunk_seconds:.0f}s"
                    )
                continue
            decoded_line = line.decode("utf-8") if isinstance(line, bytes) else str(line)
            decoded_line = decoded_line.strip()
            if not decoded_line:
                if (
                    max_idle_valid_chunk_seconds is not None
                    and now - last_valid_chunk_at > max_idle_valid_chunk_seconds
                ):
                    raise TimeoutError(
                        "Chat completion stream did not yield a valid JSON chunk "
                        f"for {max_idle_valid_chunk_seconds:.0f}s"
                    )
                continue
            if decoded_line.startswith("data:"):
                decoded_line = decoded_line[len("data:") :].strip()
            if decoded_line == "[DONE]":
                break
            if not decoded_line.startswith("{"):
                continue
            try:
                chunk = json.loads(decoded_line)
            except json.JSONDecodeError:
                logger.debug("Ignoring malformed chat completion line: %s", decoded_line[:200])
                continue
            if isinstance(chunk, dict):
                last_valid_chunk_at = time.monotonic()
                yield chunk

    @staticmethod
    def _merge_tool_call(
        tool_calls_map: Dict[Any, Dict[str, Any]],
        tool_call: Dict[str, Any],
        fallback_index: int,
    ) -> None:
        idx = tool_call.get("index", fallback_index)
        existing = tool_calls_map.setdefault(idx, {})

        for key in ("id", "type", "index"):
            if tool_call.get(key) is not None:
                existing[key] = tool_call[key]

        function_delta = tool_call.get("function")
        if isinstance(function_delta, dict):
            function = existing.setdefault("function", {})
            if function_delta.get("name"):
                function["name"] = function_delta["name"]
            if function_delta.get("arguments") is not None:
                function["arguments"] = str(function.get("arguments", "")) + str(
                    function_delta.get("arguments", "")
                )

    def _get_combined_content(self, conversation: List[Dict[str, Any]]) -> str:
        """Helper to combine all assistant generated text in case an auto-continue loop happened"""
        content_chunks = []
        for msg in conversation:
            if msg.get("role") == "assistant" and msg.get("content"):
                content_chunks.append(msg.get("content", ""))
        return "".join(content_chunks)

    @staticmethod
    def estimate_tokens(conversation: List[Dict[str, Any]]) -> int:
        """Estimate the total token count of a conversation.

        Uses a simple heuristic: ~3.5 chars per token for CJK-heavy text,
        ~4 chars per token for ASCII. This avoids a tiktoken dependency.
        """
        total_chars = 0
        for msg in conversation:
            content = msg.get("content") or ""
            if isinstance(content, str):
                total_chars += len(content)
            # Count tool call arguments as part of the context
            for tc in msg.get("tool_calls", []):
                args = tc.get("function", {}).get("arguments", "")
                if isinstance(args, str):
                    total_chars += len(args)
            # Count reasoning_content if present (e.g. DeepSeek R1)
            rc = msg.get("reasoning_content") or ""
            if isinstance(rc, str):
                total_chars += len(rc)
        # Heuristic: average 3.8 chars per token for mixed CJK/ASCII codebases
        return int(total_chars / 3.8)

    def _prepare_messages_for_model(
        self,
        conversation: List[Dict[str, Any]],
        *,
        preserve_reasoning_metadata: bool = False,
        preserve_latest_reasoning_metadata: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Build the model-facing context without mutating the full transcript.

        Tool results are the main source of context growth in long agent loops.
        Keep the most recent tool round verbatim so the model can finish the
        active reasoning step, and compact older large tool results into
        structured summaries that preserve lookup provenance and key facts.
        """
        keep_tool_ids = self._recent_tool_result_ids_to_keep(conversation)
        latest_assistant_index = next(
            (
                index
                for index in range(len(conversation) - 1, -1, -1)
                if conversation[index].get("role") == "assistant"
            ),
            None,
        )
        projected: List[Dict[str, Any]] = []
        compacted_count = 0
        original_chars = 0
        compacted_chars = 0

        for index, message in enumerate(conversation):
            role = message.get("role")
            projected_message = self._copy_message_for_model(message)
            if (
                role == "assistant"
                and not preserve_reasoning_metadata
                and not (
                    preserve_latest_reasoning_metadata and index == latest_assistant_index
                )
            ):
                # reasoning_content is provider-specific scratchpad text. It is
                # useful for continuing a truncated model turn, but replaying it
                # during normal tool rounds is expensive and disrupts prompt caching.
                projected_message.pop("reasoning_content", None)
            elif role == "tool":
                tool_id = str(message.get("tool_call_id") or "")
                content = projected_message.get("content")
                content_text = content if isinstance(content, str) else str(content or "")
                if (
                    tool_id not in keep_tool_ids
                    and len(content_text) > self.MODEL_CONTEXT_INLINE_OLD_TOOL_CHARS
                ):
                    replacement = self._compact_tool_result_content(content_text, tool_id)
                    projected_message["content"] = replacement
                    compacted_count += 1
                    original_chars += len(content_text)
                    compacted_chars += len(replacement)
            projected.append(projected_message)

        if compacted_count:
            logger.info(
                "Compacted %d old tool results for model context (%d -> %d chars)",
                compacted_count,
                original_chars,
                compacted_chars,
            )
        return projected

    def _recent_tool_result_ids_to_keep(
        self,
        conversation: List[Dict[str, Any]],
    ) -> set[str]:
        keep_ids: set[str] = set()
        rounds_seen = 0
        for message in reversed(conversation):
            tool_calls = message.get("tool_calls") or []
            if message.get("role") != "assistant" or not isinstance(tool_calls, list):
                continue
            ids = [
                str(tool_call.get("id"))
                for tool_call in tool_calls
                if isinstance(tool_call, dict) and tool_call.get("id")
            ]
            if not ids:
                continue
            keep_ids.update(ids)
            rounds_seen += 1
            if rounds_seen >= self.MODEL_CONTEXT_KEEP_RECENT_TOOL_ROUNDS:
                break
        return keep_ids

    @staticmethod
    def _copy_message_for_model(message: Dict[str, Any]) -> Dict[str, Any]:
        copied = dict(message)
        if isinstance(message.get("tool_calls"), list):
            copied["tool_calls"] = [
                (
                    {
                        **tool_call,
                        "function": dict(tool_call.get("function") or {}),
                    }
                    if isinstance(tool_call, dict)
                    else tool_call
                )
                for tool_call in message.get("tool_calls", [])
            ]
        return copied

    def _compact_tool_result_content(self, content: str, tool_call_id: str) -> str:
        parsed: Any
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = content

        summary = {
            "compacted_tool_result": True,
            "tool_call_id": tool_call_id,
            "original_chars": len(content),
            "summary": self._summarize_value(parsed),
            "instruction": (
                "The full previous tool output was compacted before this model "
                "turn. Use the summary unless exact omitted bytes are essential."
            ),
        }
        rendered = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
        return self._truncate_text(
            rendered,
            self.MODEL_CONTEXT_TOOL_RESULT_SUMMARY_CHARS,
        )

    def _summarize_value(self, value: Any, depth: int = 0, key: str = "") -> Any:
        if depth >= 4:
            return self._summarize_leaf(value, key)
        if isinstance(value, dict):
            return self._summarize_dict(value, depth)
        if isinstance(value, list):
            items = [
                self._summarize_value(item, depth + 1, key)
                for item in value[: self.MODEL_CONTEXT_SUMMARY_MAX_ITEMS]
            ]
            if len(value) > self.MODEL_CONTEXT_SUMMARY_MAX_ITEMS:
                items.append({"omitted_items": len(value) - len(items)})
            return items
        return self._summarize_leaf(value, key)

    def _summarize_dict(self, value: Dict[Any, Any], depth: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        selected_keys: List[Any] = []
        for priority_key in self._SUMMARY_PRIORITY_KEYS:
            if priority_key in value:
                selected_keys.append(priority_key)
        for key in value:
            if key not in selected_keys:
                selected_keys.append(key)
            if len(selected_keys) >= self.MODEL_CONTEXT_SUMMARY_MAX_KEYS:
                break

        for raw_key in selected_keys[: self.MODEL_CONTEXT_SUMMARY_MAX_KEYS]:
            str_key = str(raw_key)
            result[str_key] = self._summarize_value(value[raw_key], depth + 1, str_key)

        omitted = len(value) - len(selected_keys[: self.MODEL_CONTEXT_SUMMARY_MAX_KEYS])
        if omitted > 0:
            result["omitted_keys"] = omitted
        return result

    def _summarize_leaf(self, value: Any, key: str = "") -> Any:
        if isinstance(value, str):
            limit = (
                self.MODEL_CONTEXT_SUMMARY_HEAVY_STRING_CHARS
                if key in self._SUMMARY_HEAVY_KEYS
                else self.MODEL_CONTEXT_SUMMARY_STRING_CHARS
            )
            return self._truncate_text(value, limit)
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return self._truncate_text(str(value), self.MODEL_CONTEXT_SUMMARY_STRING_CHARS)

    @staticmethod
    def _truncate_text(value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        omitted = len(value) - limit
        head = max(0, limit - 48)
        return f"{value[:head]}...[truncated {omitted} chars]"

    def run_conversation_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools_schema: List[Dict[str, Any]],
        tool_executor: Callable[[str, Dict[str, Any]], Dict[str, Any]],
        max_iterations: int = 50,
        trace_agent: Optional[str] = None,
        trace_label: Optional[str] = None,
        max_identical_tool_calls: int = 2,
        terminal_tool_name: Optional[str] = None,
        terminal_tool_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        terminal_tool_validator: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        terminal_tool_required: bool = False,
        max_identical_invalid_terminal_calls: int = 3,
        max_invalid_terminal_calls: int = 5,
        preserve_reasoning_metadata: bool = False,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Run a conversation loop with tool calling support.
        """
        conversation = messages.copy()
        iterations = 0
        tool_call_history: Dict[str, List[Dict[str, Any]]] = {}
        loop_guard_recovery: Optional[Dict[str, Any]] = None
        loop_guard_disabled_tools: Set[str] = set()
        cumulative_prompt_tokens = 0
        cumulative_completion_tokens = 0
        warned_low_iterations = False
        low_iteration_threshold = max(3, min(10, max_iterations // 10 or 1))
        last_finish_reason: Optional[str] = None
        last_provider_model: Optional[str] = None
        last_message: Dict[str, Any] = {}
        terminal_payload: Optional[Dict[str, Any]] = None
        terminal_tool_valid = False
        terminal_tool_call_count = 0
        terminal_invalid_call_count = 0
        terminal_failure_history: Dict[str, List[Dict[str, Any]]] = {}
        loop_guard_fired = False
        if terminal_tool_handler is None and terminal_tool_validator is not None:
            terminal_tool_handler = terminal_tool_validator
        conversation_started_monotonic = time.monotonic()
        recorder = get_conversation_recorder()
        trace_session = (
            recorder.begin_session(
                trace_agent or "unknown_agent",
                trace_label,
                tools_schema_hash=self._tools_schema_hash(tools_schema),
            )
            if recorder
            else None
        )

        def _record_session_end_traced(
            final_iterations: int,
            final_tokens: int,
            *,
            truncated: bool,
            finish_reason_value: Optional[str],
            terminal_valid: Optional[bool],
        ) -> None:
            if not (recorder and trace_session):
                return
            recorder.record_session_end(
                trace_session,
                final_iterations,
                final_tokens,
                truncated=truncated,
                cumulative_prompt_tokens=cumulative_prompt_tokens,
                cumulative_completion_tokens=cumulative_completion_tokens,
                cumulative_total_tokens=cumulative_prompt_tokens
                + cumulative_completion_tokens,
                wall_seconds=max(0.0, time.monotonic() - conversation_started_monotonic),
                finish_reason=finish_reason_value,
                loop_guard_triggered=loop_guard_fired or None,
                terminal_tool_valid=terminal_valid,
            )

        while iterations < max_iterations:
            iterations += 1
            remaining_after_this = max_iterations - iterations
            max_iteration_final = iterations >= max_iterations
            executor_requested_final = False
            start_tool_iteration = getattr(
                tool_executor,
                "_zscope_start_iteration",
                None,
            )
            if callable(start_tool_iteration):
                try:
                    executor_requested_final = bool(start_tool_iteration(iterations))
                except Exception as exc:
                    logger.warning(
                        "Tool executor iteration guard failed; forcing final synthesis: %s",
                        exc,
                    )
                    executor_requested_final = True
            force_no_tool_final = executor_requested_final
            final_iteration = max_iteration_final or force_no_tool_final
            if max_iteration_final:
                final_instruction = (
                    f"This is the final allowed iteration ({iterations}/{max_iterations}). "
                    "Tool use is now disabled. Produce the best final answer from the current "
                    "conversation context. If the expected output is JSON, output valid JSON now. "
                    "Do not ask for more tools or more turns."
                )
                if terminal_tool_name:
                    final_instruction = (
                        f"This is the final allowed iteration ({iterations}/{max_iterations}). "
                        "Regular tool use is now disabled. Submit the required final result by "
                        f"calling {terminal_tool_name}; do not ask for more tools or more turns."
                    )
                conversation.append(
                    {
                        "role": "user",
                        "content": final_instruction,
                    }
                )
                self._record_control_event(
                    trace_session,
                    iterations,
                    "final_instruction",
                    {
                        "iteration": iterations,
                        "max_iterations": max_iterations,
                        "terminal_tool_name": terminal_tool_name,
                    },
                )
            elif force_no_tool_final:
                self._record_control_event(
                    trace_session, iterations, "forced_final_by_executor"
                )
            elif not warned_low_iterations and remaining_after_this <= low_iteration_threshold:
                warned_low_iterations = True
                conversation.append(
                    {
                        "role": "user",
                        "content": (
                            f"Iteration budget warning: after this turn only {remaining_after_this} "
                            f"of {max_iterations} iterations remain. Stop expanding the search unless "
                            "a missing fact is essential; prefer synthesizing the final result from "
                            "the evidence already in this conversation."
                        ),
                    }
                )
                self._record_control_event(
                    trace_session,
                    iterations,
                    "low_iteration_warning",
                    {
                        "remaining_after_this": remaining_after_this,
                        "max_iterations": max_iterations,
                    },
                )

            model_conversation = self._prepare_messages_for_model(
                conversation,
                preserve_reasoning_metadata=preserve_reasoning_metadata,
                preserve_latest_reasoning_metadata=last_finish_reason == "length",
            )
            ctx_tokens = self.estimate_tokens(model_conversation)
            raw_ctx_tokens = self.estimate_tokens(conversation)
            logger.info(
                "Conversation iteration %s/%s | model context ≈%s tokens (raw ≈%s)",
                iterations,
                max_iterations,
                f"{ctx_tokens:,}",
                f"{raw_ctx_tokens:,}",
            )

            # Call LLM
            request_tools = (
                None
                if final_iteration
                else [
                    schema
                    for schema in tools_schema
                    if not (
                        isinstance(schema, dict)
                        and isinstance(schema.get("function"), dict)
                        and schema["function"].get("name") in loop_guard_disabled_tools
                        and schema["function"].get("name") != terminal_tool_name
                    )
                ]
            )
            if final_iteration and terminal_tool_name:
                terminal_schemas = [
                    schema
                    for schema in tools_schema
                    if isinstance(schema, dict)
                    and isinstance(schema.get("function"), dict)
                    and schema["function"].get("name") == terminal_tool_name
                ]
                request_tools = terminal_schemas or None
            completion_kwargs: Dict[str, Any] = {
                "tools": request_tools,
                "trace_agent": trace_agent,
                "trace_label": trace_label,
                "trace_iteration": iterations,
                "trace_session": trace_session,
            }
            if max_tokens is not None:
                completion_kwargs["max_tokens"] = max_tokens
            if temperature is not None:
                completion_kwargs["temperature"] = temperature
            response = self.chat_completion(model_conversation, **completion_kwargs)

            # Extract assistant message
            choice = response.get("choices", [{}])[0]
            message = choice.get("message", {})
            finish_reason = choice.get("finish_reason")
            provider_model = response.get("model") or (self.models[0] if self.models else None)
            last_finish_reason = finish_reason
            last_provider_model = provider_model
            last_message = message
            prompt_tokens, completion_tokens = self._response_token_usage(
                response,
                model_conversation,
                message,
            )
            cumulative_prompt_tokens += prompt_tokens
            cumulative_completion_tokens += completion_tokens

            # Add assistant message to conversation
            conversation.append(message)
            assistant_message_index = len(conversation)

            # Some compatible providers return finish_reason=stop even when
            # the message carries tool_calls or XML-style invoke tags.
            if (
                finish_reason == "stop"
                and not message.get("tool_calls")
                and "<invoke name=" not in str(message.get("content", ""))
            ):
                if terminal_tool_required and iterations < max_iterations:
                    conversation.append(
                        {
                            "role": "user",
                            "content": (
                                "Do not return prose. Complete the evidence review and submit the "
                                f"final result by calling {terminal_tool_name}."
                            ),
                        }
                    )
                    self._record_control_event(
                        trace_session,
                        iterations,
                        "terminal_prose_reprompt",
                        {"reason": "no_terminal_call"},
                    )
                    continue
                content = self._get_combined_content(conversation)
                final_tokens = self.estimate_tokens(
                    self._prepare_messages_for_model(
                        conversation,
                        preserve_reasoning_metadata=preserve_reasoning_metadata,
                    )
                )
                logger.info(
                    f"Conversation complete: {iterations} iterations, final context ≈ {final_tokens:,} tokens"
                )
                _record_session_end_traced(
                    iterations,
                    final_tokens,
                    truncated=False,
                    finish_reason_value=finish_reason,
                    terminal_valid=terminal_tool_valid,
                )
                result_payload = {
                    "content": content,
                    "conversation": conversation,
                    "iterations": iterations,
                    "context_tokens": final_tokens,
                    "api_call_count": iterations,
                    "cumulative_prompt_tokens": cumulative_prompt_tokens,
                    "cumulative_completion_tokens": cumulative_completion_tokens,
                    "cumulative_total_tokens": cumulative_prompt_tokens
                    + cumulative_completion_tokens,
                    "tool_call_count": self._count_tool_result_messages(conversation),
                    "finish_reason": finish_reason,
                    "provider_model": provider_model,
                    "last_assistant_preview": self._assistant_preview(message),
                    "terminal_tool_payload": terminal_payload,
                    "terminal_tool_name": terminal_tool_name,
                    "terminal_tool_valid": terminal_tool_valid,
                    "terminal_tool_call_count": terminal_tool_call_count,
                    "terminal_invalid_call_count": terminal_invalid_call_count,
                }
                if loop_guard_recovery:
                    result_payload.update(
                        {
                            "loop_guard_triggered": True,
                            "loop_guard_recovered": True,
                            "repeated_tool_call": loop_guard_recovery,
                        }
                    )
                return result_payload

            if finish_reason == "length":
                logger.warning(
                    f"Model {self.models[0] if self.models else 'unknown'} output truncated! Prompting to continue..."
                )
                conversation.append({"role": "user", "content": "请继续"})
                self._record_control_event(
                    trace_session,
                    iterations,
                    "length_continuation",
                    {"finish_reason": "length"},
                )
                continue

            # Handle tool calls
            tool_calls = message.get("tool_calls", [])
            final_iteration_has_only_terminal = bool(
                terminal_tool_name
                and tool_calls
                and all(
                    isinstance(call, dict)
                    and isinstance(call.get("function"), dict)
                    and call["function"].get("name") == terminal_tool_name
                    for call in tool_calls
                )
            )
            if final_iteration and tool_calls and not final_iteration_has_only_terminal:
                logger.warning(
                    "Model returned %d tool calls after tool use was disabled.",
                    len(tool_calls),
                )
                self._record_control_event(
                    trace_session,
                    iterations,
                    "final_iteration_tool_calls_rejected",
                    {"tool_call_count": len(tool_calls)},
                )
                final_tokens = self.estimate_tokens(
                    self._prepare_messages_for_model(
                        conversation,
                        preserve_reasoning_metadata=preserve_reasoning_metadata,
                    )
                )
                _record_session_end_traced(
                    iterations,
                    final_tokens,
                    truncated=max_iteration_final,
                    finish_reason_value=finish_reason,
                    terminal_valid=terminal_tool_valid,
                )
                result_payload = {
                    "content": self._get_combined_content(conversation),
                    "conversation": conversation,
                    "iterations": iterations,
                    "truncated": max_iteration_final,
                    "context_tokens": final_tokens,
                    "api_call_count": iterations,
                    "cumulative_prompt_tokens": cumulative_prompt_tokens,
                    "cumulative_completion_tokens": cumulative_completion_tokens,
                    "cumulative_total_tokens": cumulative_prompt_tokens
                    + cumulative_completion_tokens,
                    "tool_call_count": self._count_tool_result_messages(conversation),
                    "finish_reason": finish_reason,
                    "provider_model": provider_model,
                    "final_tool_call_after_tools_disabled": True,
                    "final_tool_call_without_json": True,
                    "final_tool_call_count": len(tool_calls),
                    "terminal_tool_payload": terminal_payload,
                    "terminal_tool_name": terminal_tool_name,
                    "terminal_tool_valid": terminal_tool_valid,
                    "terminal_tool_call_count": terminal_tool_call_count,
                    "terminal_invalid_call_count": terminal_invalid_call_count,
                    "last_assistant_preview": self._assistant_preview(message),
                }
                if loop_guard_recovery:
                    result_payload.update(
                        {
                            "loop_guard_triggered": True,
                            "loop_guard_recovered": False,
                            "repeated_tool_call": loop_guard_recovery,
                        }
                    )
                return result_payload

            # --- XML Fallback (For GLM/Minimax models that emit raw text invoke tags) ---
            content = message.get("content", "")
            if not final_iteration and not tool_calls and "<invoke name=" in content:
                import uuid

                invokes = re.finditer(r'<invoke name="([^"]+)">([\s\S]*?)(?:</invoke>|$)', content)
                for match in invokes:
                    xml_func_name = match.group(1)
                    xml_param_str = match.group(2)
                    xml_args = {}
                    for param_match in re.finditer(
                        r'<parameter name="([^"]+)">([\s\S]*?)(?=(?:</parameter>|<parameter|</invoke>|$))',
                        xml_param_str,
                    ):
                        # Attempt to cast numeric strings to int if applicable, else keep string
                        xml_val: Any = param_match.group(2).strip()
                        xml_val = re.sub(r"</.*$", "", str(xml_val), flags=re.DOTALL).strip()
                        if str(xml_val).isdigit():
                            xml_val = int(xml_val)
                        xml_args[param_match.group(1)] = xml_val

                    tool_calls.append(
                        {
                            "id": f"call_xml_{uuid.uuid4().hex[:10]}",
                            "type": "function",
                            "function": {
                                "name": xml_func_name,
                                "arguments": json.dumps(xml_args, ensure_ascii=False),
                            },
                        }
                    )
                # If we synthetically built tool calls, we should ensure the LLM knows it made them.
                if tool_calls and "tool_calls" not in message:
                    message["tool_calls"] = tool_calls
            # --------------------------------------------------------------------------

            if not tool_calls:
                if terminal_tool_required and iterations < max_iterations:
                    conversation.append(
                        {
                            "role": "user",
                            "content": (
                                "A final tool call is required. Do not write a snapshot in prose or JSON; "
                                f"call {terminal_tool_name} exactly once with the complete payload."
                            ),
                        }
                    )
                    self._record_control_event(
                        trace_session,
                        iterations,
                        "terminal_prose_reprompt",
                        {"reason": "no_tool_calls"},
                    )
                    continue
                content = self._get_combined_content(conversation)
                final_tokens = self.estimate_tokens(
                    self._prepare_messages_for_model(
                        conversation,
                        preserve_reasoning_metadata=preserve_reasoning_metadata,
                    )
                )
                logger.info(
                    f"Conversation complete (no more tool calls): {iterations} iterations, final context ≈ {final_tokens:,} tokens"
                )
                _record_session_end_traced(
                    iterations,
                    final_tokens,
                    truncated=False,
                    finish_reason_value=finish_reason,
                    terminal_valid=terminal_tool_valid,
                )
                result_payload = {
                    "content": content,
                    "conversation": conversation,
                    "iterations": iterations,
                    "context_tokens": final_tokens,
                    "api_call_count": iterations,
                    "cumulative_prompt_tokens": cumulative_prompt_tokens,
                    "cumulative_completion_tokens": cumulative_completion_tokens,
                    "cumulative_total_tokens": cumulative_prompt_tokens
                    + cumulative_completion_tokens,
                    "tool_call_count": self._count_tool_result_messages(conversation),
                    "finish_reason": finish_reason,
                    "provider_model": provider_model,
                    "last_assistant_preview": self._assistant_preview(message),
                    "terminal_tool_payload": terminal_payload,
                    "terminal_tool_name": terminal_tool_name,
                    "terminal_tool_valid": terminal_tool_valid,
                    "terminal_tool_call_count": terminal_tool_call_count,
                    "terminal_invalid_call_count": terminal_invalid_call_count,
                }
                if loop_guard_recovery:
                    result_payload.update(
                        {
                            "loop_guard_triggered": True,
                            "loop_guard_recovered": True,
                            "repeated_tool_call": loop_guard_recovery,
                        }
                    )
                return result_payload

            # Execute each tool call
            loop_guard_tools_triggered_this_iteration: List[str] = []
            terminal_calls = []
            for candidate in tool_calls:
                candidate_function = (
                    candidate.get("function", {}) if isinstance(candidate, dict) else {}
                )
                if terminal_tool_name and candidate_function.get("name") == terminal_tool_name:
                    terminal_calls.append(candidate)

            if terminal_calls:
                terminal_tool_call_count += len(terminal_calls)
                mixed_calls = len(terminal_calls) != len(tool_calls)
                duplicate_calls = len(terminal_calls) > 1
                for terminal_call in terminal_calls:
                    terminal_id = terminal_call.get("id")
                    terminal_function = terminal_call.get("function", {})
                    raw_terminal_args = terminal_function.get("arguments", "{}")
                    try:
                        terminal_args = self._parse_tool_args(raw_terminal_args)
                        terminal_function["arguments"] = json.dumps(
                            terminal_args, ensure_ascii=False
                        )
                    except Exception as exc:
                        terminal_args = {}
                        terminal_function["arguments"] = json.dumps(terminal_args)
                        exc_text = str(exc)
                    else:
                        exc_text = ""

                    validation: Dict[str, Any] = {"valid": True, "payload": terminal_args}
                    if exc_text:
                        validation = {"valid": False, "error": exc_text}
                    elif mixed_calls:
                        validation = {
                            "valid": False,
                            "error": "The terminal final tool cannot be combined with other tool calls; retry it alone.",
                        }
                    elif duplicate_calls:
                        validation = {
                            "valid": False,
                            "error": "Only one terminal final tool call is allowed in a conversation.",
                        }
                    elif terminal_tool_handler:
                        try:
                            handled = terminal_tool_handler(terminal_args)
                            if isinstance(handled, dict):
                                validation = handled
                            else:
                                validation = {"valid": bool(handled), "payload": terminal_args}
                        except Exception as exc:
                            validation = {"valid": False, "error": str(exc)}

                    if validation.get("valid"):
                        terminal_payload = validation.get("payload", terminal_args)
                        terminal_tool_valid = True
                        if recorder and trace_session:
                            recorder.record_terminal_tool(
                                trace_session,
                                iterations,
                                terminal_tool_name,
                                terminal_args,
                                True,
                                tool_call_id=terminal_id,
                            )
                        final_tokens = self.estimate_tokens(
                            self._prepare_messages_for_model(
                                conversation,
                                preserve_reasoning_metadata=preserve_reasoning_metadata,
                            )
                        )
                        _record_session_end_traced(
                            iterations,
                            final_tokens,
                            truncated=False,
                            finish_reason_value=finish_reason,
                            terminal_valid=terminal_tool_valid,
                        )
                        return {
                            "content": str(message.get("content") or ""),
                            "conversation": conversation,
                            "message": message,
                            "terminal_tool_payload": terminal_payload,
                            "terminal_tool_name": terminal_tool_name,
                            "terminal_tool_valid": True,
                            "terminal_tool_call_count": terminal_tool_call_count,
                            "terminal_invalid_call_count": terminal_invalid_call_count,
                            "iterations": iterations,
                            "context_tokens": final_tokens,
                            "api_call_count": iterations,
                            "cumulative_prompt_tokens": cumulative_prompt_tokens,
                            "cumulative_completion_tokens": cumulative_completion_tokens,
                            "cumulative_total_tokens": cumulative_prompt_tokens
                            + cumulative_completion_tokens,
                            "tool_call_count": self._count_tool_result_messages(conversation),
                            "final_tool_call_count": terminal_tool_call_count,
                            "finish_reason": finish_reason,
                            "provider_model": provider_model,
                            "last_assistant_preview": self._assistant_preview(message),
                        }

                    validation_error = str(
                        validation.get("error") or "Invalid terminal tool payload."
                    )
                    error_result = {
                        "success": False,
                        "terminal_tool": terminal_tool_name,
                        "terminal_tool_valid": False,
                        "error": validation_error,
                    }
                    conversation.append(
                        {
                            "role": "tool",
                            "tool_call_id": terminal_id,
                            "terminal_tool_result": True,
                            "content": json.dumps(error_result, ensure_ascii=False),
                        }
                    )
                    if recorder and trace_session:
                        recorder.record_terminal_tool(
                            trace_session,
                            iterations,
                            terminal_tool_name,
                            terminal_args,
                            False,
                            validation_error,
                            tool_call_id=terminal_id,
                        )
                    terminal_invalid_call_count += 1
                    failure_signature = self._terminal_failure_signature(
                        terminal_tool_name,
                        terminal_args,
                        raw_arguments=raw_terminal_args,
                        parse_failed=bool(exc_text),
                        error=validation_error,
                    )
                    failure_record = {
                        "iteration": iterations,
                        "tool_call_id": terminal_id,
                        "arguments": raw_terminal_args if exc_text else terminal_args,
                        "error": error_result["error"],
                    }
                    identical_failures = terminal_failure_history.setdefault(
                        failure_signature,
                        [],
                    )
                    identical_failures.append(failure_record)

                    guard_reason: Optional[str] = None
                    if (
                        max_identical_invalid_terminal_calls > 0
                        and len(identical_failures) >= max_identical_invalid_terminal_calls
                    ):
                        guard_reason = "identical_invalid_terminal_call_limit"
                    elif (
                        max_invalid_terminal_calls > 0
                        and terminal_invalid_call_count >= max_invalid_terminal_calls
                    ):
                        guard_reason = "invalid_terminal_call_limit"

                    if guard_reason:
                        repeated_terminal_tool_call = None
                        if guard_reason == "identical_invalid_terminal_call_limit":
                            repeated_terminal_tool_call = {
                                "tool": terminal_tool_name,
                                "arguments": failure_record["arguments"],
                                "error": error_result["error"],
                                "repeat_count": len(identical_failures),
                                "first_seen": identical_failures[0],
                                "latest_seen": identical_failures[-1],
                            }
                        final_tokens = self.estimate_tokens(
                            self._prepare_messages_for_model(
                                conversation,
                                preserve_reasoning_metadata=preserve_reasoning_metadata,
                            )
                        )
                        logger.warning(
                            "Terminal tool loop guard triggered tool=%s reason=%s "
                            "invalid_calls=%d identical_failures=%d",
                            terminal_tool_name,
                            guard_reason,
                            terminal_invalid_call_count,
                            len(identical_failures),
                        )
                        loop_guard_fired = True
                        self._record_loop_guard_event(
                            trace_session,
                            iterations,
                            tool=terminal_tool_name,
                            repeat_count=len(identical_failures),
                            reason=guard_reason,
                            scope="terminal",
                        )
                        _record_session_end_traced(
                            iterations,
                            final_tokens,
                            truncated=False,
                            finish_reason_value=finish_reason,
                            terminal_valid=terminal_tool_valid,
                        )
                        result_payload = {
                            "content": str(message.get("content") or ""),
                            "conversation": conversation,
                            "message": message,
                            "iterations": iterations,
                            "truncated": False,
                            "context_tokens": final_tokens,
                            "api_call_count": iterations,
                            "cumulative_prompt_tokens": cumulative_prompt_tokens,
                            "cumulative_completion_tokens": cumulative_completion_tokens,
                            "cumulative_total_tokens": cumulative_prompt_tokens
                            + cumulative_completion_tokens,
                            "tool_call_count": self._count_tool_result_messages(conversation),
                            "finish_reason": finish_reason,
                            "provider_model": provider_model,
                            "final_tool_call_count": terminal_tool_call_count,
                            "last_assistant_preview": self._assistant_preview(message),
                            "terminal_tool_payload": terminal_payload,
                            "terminal_tool_name": terminal_tool_name,
                            "terminal_tool_valid": False,
                            "terminal_tool_call_count": terminal_tool_call_count,
                            "terminal_invalid_call_count": terminal_invalid_call_count,
                            "terminal_loop_guard_triggered": True,
                            "terminal_loop_guard_reason": guard_reason,
                        }
                        if repeated_terminal_tool_call is not None:
                            result_payload["repeated_terminal_tool_call"] = (
                                repeated_terminal_tool_call
                            )
                        return result_payload
                tool_calls = [call for call in tool_calls if call not in terminal_calls]

            for tool_call in tool_calls:
                tool_id = tool_call.get("id")
                function = tool_call.get("function", {})
                func_name = function.get("name")
                func_args_str = function.get("arguments", "{}")

                logger.info(f"Tool call: {func_name}")

                tool_started = time.monotonic()
                func_args: Dict[str, Any] = {}
                try:
                    func_args = self._parse_tool_args(func_args_str)

                    # VERY IMPORTANT: Re-serialize the corrected dict back into the conversation history
                    # so that strict upstreams like GLM-4/5 do not throw 400 Bad Request on "Expecting ','"
                    function["arguments"] = json.dumps(func_args, ensure_ascii=False)
                    if recorder and trace_session:
                        recorder.record_tool_call(
                            trace_session,
                            iterations,
                            func_name,
                            func_args,
                            tool_call_id=tool_id,
                        )

                    signature = self._tool_call_signature(func_name, func_args)
                    previous_calls = tool_call_history.get(signature, [])
                    covered_snippet_call = None
                    if not (
                        max_identical_tool_calls > 0
                        and len(previous_calls) >= max_identical_tool_calls
                    ):
                        covered_snippet_call = self._find_covering_file_snippet_call(
                            tool_call_history,
                            signature,
                            func_args,
                        )
                    cached_replayed = any(call.get("cached_replay") for call in previous_calls)
                    cached_previous_result = self._last_replayable_tool_result(previous_calls)
                    repeat_notice = self._build_repeat_tool_notice(
                        func_name,
                        func_args,
                        tool_id,
                        previous_calls,
                    )
                    if func_name in loop_guard_disabled_tools:
                        repeated_call_count = len(previous_calls) + 1
                        result = {
                            "success": False,
                            "error": (
                                "This tool was disabled by the loop guard after a repeated "
                                "call. Use another available tool or produce the final answer."
                            ),
                            "loop_guard_disabled_tool": True,
                            **repeat_notice,
                        }
                        logger.warning(
                            "Rejected call to tool disabled by loop guard: %s %s",
                            func_name,
                            func_args,
                        )
                    elif covered_snippet_call is not None:
                        repeated_call_count = 0
                        result = self._slice_covering_file_snippet_result(
                            covered_snippet_call,
                            func_args,
                        )
                        if result is None:
                            result = tool_executor(func_name, func_args)
                        else:
                            result["cached_tool_result"] = True
                            result["covered_file_snippet_replay"] = True
                            result["repeat_call_warning"] = self._build_covered_file_snippet_notice(
                                func_args,
                                tool_id,
                                covered_snippet_call,
                            )
                            logger.warning(
                                "Replayed sliced cached result for covered get_file_snippet range: "
                                "%s (covered by %s)",
                                func_args,
                                covered_snippet_call.get("arguments"),
                            )
                    elif (
                        max_identical_tool_calls > 0
                        and len(previous_calls) >= max_identical_tool_calls
                    ):
                        repeated_call_count = len(previous_calls) + 1
                        if cached_previous_result is not None and not cached_replayed:
                            result = dict(cached_previous_result)
                            result["cached_tool_result"] = True
                            result["repeat_call_warning"] = {
                                **repeat_notice,
                                "instruction": (
                                    "This is a cached replay of the previous successful "
                                    "tool result for the identical call. Use this content "
                                    "now; do not request the same tool arguments again."
                                ),
                            }
                            logger.warning(
                                "Replayed cached result for repeated identical tool call: "
                                "%s %s (repeat #%d)",
                                func_name,
                                func_args,
                                repeated_call_count,
                            )
                        else:
                            result = {
                                "success": False,
                                "error": (
                                    "Repeated identical tool call blocked by the loop guard. "
                                    "The previous result was already replayed or unavailable; "
                                    "produce the best final answer from available evidence."
                                ),
                                "repeat_call_guard": True,
                                **repeat_notice,
                            }
                            logger.warning(
                                "Blocked repeated identical tool call: %s %s (repeat #%d)",
                                func_name,
                                func_args,
                                repeated_call_count,
                            )
                            if cached_previous_result is not None:
                                result = dict(cached_previous_result)
                                result["cached_tool_result"] = True
                                result["repeat_call_guard"] = True
                                result["repeat_call_warning"] = {
                                    **repeat_notice,
                                    "instruction": (
                                        "This repeated tool call is blocked by the loop guard. "
                                        "The latest tool message replays the previous successful "
                                        "result. Use this content now and produce the final answer; "
                                        "tool use will be disabled for the next response."
                                    ),
                                }
                    else:
                        repeated_call_count = 0
                        set_tool_iteration = getattr(
                            tool_executor,
                            "_zscope_set_iteration",
                            None,
                        )
                        if callable(set_tool_iteration):
                            set_tool_iteration(iterations)
                        result = tool_executor(func_name, func_args)
                        if previous_calls and isinstance(result, dict):
                            result = dict(result)
                            result["repeat_call_warning"] = repeat_notice

                    tool_result_message_index = len(conversation) + 1
                    conversation.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_id,
                            "content": json.dumps(result, ensure_ascii=False),
                        }
                    )
                    tool_call_history.setdefault(signature, []).append(
                        {
                            "iteration": iterations,
                            "tool": func_name,
                            "tool_call_id": tool_id,
                            "assistant_message_index": assistant_message_index,
                            "tool_result_message_index": tool_result_message_index,
                            "arguments": func_args,
                            "blocked": bool(
                                isinstance(result, dict) and result.get("repeat_call_guard")
                            ),
                            "cached_replay": bool(
                                isinstance(result, dict) and result.get("cached_tool_result")
                            ),
                            "result": result if isinstance(result, dict) else None,
                        }
                    )
                    if recorder and trace_session:
                        recorder.record_tool_result(
                            trace_session,
                            iterations,
                            func_name,
                            func_args,
                            result,
                            tool_call_id=tool_id,
                            duration_ms=max(
                                0, int(round((time.monotonic() - tool_started) * 1000))
                            ),
                            blocked=bool(
                                isinstance(result, dict) and result.get("repeat_call_guard")
                            ),
                            cached_replay=bool(
                                isinstance(result, dict) and result.get("cached_tool_result")
                            ),
                            repeat_count=repeated_call_count,
                        )

                    if isinstance(result, dict) and result.get("repeat_call_guard"):
                        loop_guard_disabled_tools.add(func_name)
                        loop_guard_recovery = {
                            "tool": func_name,
                            "arguments": func_args,
                            "repeat_count": repeated_call_count,
                            "disabled_tools": sorted(loop_guard_disabled_tools),
                        }
                        logger.error(
                            "Conversation hit repeated identical tool call; disabling only "
                            "the offending tool: "
                            "%s %s (repeat #%d)",
                            func_name,
                            func_args,
                            repeated_call_count,
                        )
                        loop_guard_fired = True
                        self._record_loop_guard_event(
                            trace_session,
                            iterations,
                            tool=func_name,
                            repeat_count=repeated_call_count,
                            disabled_tools=sorted(loop_guard_disabled_tools),
                            scope="tool",
                            recovered=False,
                        )
                        if func_name not in loop_guard_tools_triggered_this_iteration:
                            loop_guard_tools_triggered_this_iteration.append(func_name)

                except Exception as e:
                    logger.error(f"Tool execution failed: {e}")
                    conversation.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_id,
                            "content": json.dumps({"error": str(e)}),
                        }
                    )
                    if recorder and trace_session:
                        recorder.record_tool_result(
                            trace_session,
                            iterations,
                            func_name,
                            func_args,
                            {},
                            error=str(e),
                            tool_call_id=tool_id,
                            duration_ms=max(
                                0, int(round((time.monotonic() - tool_started) * 1000))
                            ),
                            args_raw=func_args_str if not func_args else None,
                        )
            if loop_guard_tools_triggered_this_iteration:
                disabled_names = ", ".join(loop_guard_tools_triggered_this_iteration)
                conversation.append(
                    {
                        "role": "user",
                        "content": (
                            "The loop guard blocked repeated calls and disabled only these tools: "
                            f"{disabled_names}. Their latest tool messages contain the cached "
                            "results or available evidence. Other tools remain available; use them "
                            "only if needed, then produce the required final answer."
                        ),
                    }
                )
                continue

        if iterations >= max_iterations:
            logger.warning(
                f"Conversation reached max iterations ({max_iterations}). Possible loop."
            )
            # Log the last 2 assistant messages and tool results for debugging
            history_summary = []
            for msg in conversation[-4:]:
                role = msg.get("role")
                if role == "assistant":
                    content = msg.get("content") or "Tool Call"
                    history_summary.append(f"Assistant: {content[:100]}...")
                elif role == "tool":
                    content_preview = str(msg.get("content", ""))
                    history_summary.append(f"Tool Result: {content_preview[:100]}...")
            logger.debug(f"Last steps: {history_summary}")

        final_tokens = self.estimate_tokens(
            self._prepare_messages_for_model(
                conversation,
                preserve_reasoning_metadata=preserve_reasoning_metadata,
            )
        )
        logger.info(
            f"Conversation ended (truncated={iterations >= max_iterations}): {iterations} iterations, final context ≈ {final_tokens:,} tokens"
        )
        _record_session_end_traced(
            iterations,
            final_tokens,
            truncated=iterations >= max_iterations,
            finish_reason_value=last_finish_reason,
            terminal_valid=terminal_tool_valid,
        )
        result_payload = {
            "content": conversation[-1].get("content", "") if not message.get("tool_calls") else "",
            "conversation": conversation,
            "iterations": iterations,
            "truncated": iterations >= max_iterations,
            "context_tokens": final_tokens,
            "api_call_count": iterations,
            "cumulative_prompt_tokens": cumulative_prompt_tokens,
            "cumulative_completion_tokens": cumulative_completion_tokens,
            "cumulative_total_tokens": cumulative_prompt_tokens + cumulative_completion_tokens,
            "tool_call_count": self._count_tool_result_messages(conversation),
            "finish_reason": last_finish_reason,
            "provider_model": last_provider_model,
            "final_tool_call_count": len(last_message.get("tool_calls") or []),
            "last_assistant_preview": self._assistant_preview(last_message),
            "terminal_tool_payload": terminal_payload,
            "terminal_tool_name": terminal_tool_name,
            "terminal_tool_valid": terminal_tool_valid,
            "terminal_tool_call_count": terminal_tool_call_count,
            "terminal_invalid_call_count": terminal_invalid_call_count,
        }
        if loop_guard_recovery:
            result_payload.update(
                {
                    "loop_guard_triggered": True,
                    "loop_guard_recovered": not result_payload.get("truncated"),
                    "repeated_tool_call": loop_guard_recovery,
                }
            )
        return result_payload

    @classmethod
    def _terminal_failure_signature(
        cls,
        tool_name: Any,
        arguments: Dict[str, Any],
        *,
        raw_arguments: Any,
        parse_failed: bool,
        error: str,
    ) -> str:
        if parse_failed:
            normalized_arguments: Any = str(raw_arguments)
        else:
            normalized_arguments = cls._normalize_tool_args(str(tool_name or ""), arguments)
        return json.dumps(
            {
                "tool": str(tool_name or ""),
                "arguments": normalized_arguments,
                "error": str(error or ""),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _count_tool_result_messages(conversation: List[Dict[str, Any]]) -> int:
        return sum(
            1
            for message in conversation
            if message.get("role") == "tool" and not message.get("terminal_tool_result")
        )

    @staticmethod
    def _assistant_preview(message: Dict[str, Any], limit: int = 240) -> str:
        content = str(message.get("content") or "")
        if not content and message.get("reasoning_content"):
            content = str(message.get("reasoning_content") or "")
        if not content and message.get("tool_calls"):
            names = [
                str((tool_call.get("function") or {}).get("name") or "unknown")
                for tool_call in message.get("tool_calls") or []
            ]
            content = "tool_calls=" + ",".join(names)
        return LLMClient._truncate_text(content, limit)

    @classmethod
    def _response_token_usage(
        cls,
        response: Dict[str, Any],
        prompt_messages: List[Dict[str, Any]],
        assistant_message: Dict[str, Any],
    ) -> tuple[int, int]:
        raw_usage = response.get("usage")
        usage: Dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        if not isinstance(prompt_tokens, int):
            prompt_tokens = cls.estimate_tokens(prompt_messages)
        if not isinstance(completion_tokens, int):
            completion_tokens = cls.estimate_tokens([assistant_message])
        return max(0, prompt_tokens), max(0, completion_tokens)

    @classmethod
    def _tool_call_signature(cls, tool_name: Any, arguments: Dict[str, Any]) -> str:
        """Return a stable signature for detecting identical tool calls."""
        normalized_tool = str(tool_name or "")
        normalized_args = cls._normalize_tool_args(normalized_tool, arguments)
        return (
            normalized_tool
            + ":"
            + json.dumps(
                normalized_args,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    @classmethod
    def _normalize_tool_args(cls, tool_name: str, value: Any) -> Any:
        if isinstance(value, dict):
            normalized = {
                str(key): cls._normalize_tool_args(tool_name, val) for key, val in value.items()
            }
            if tool_name == "get_function_impl" and "max_lines" not in normalized:
                normalized["max_lines"] = 200
            if tool_name in {"get_call_graph", "query_pointer_alias"} and "limit" not in normalized:
                normalized["limit"] = 30
            return normalized
        if isinstance(value, list):
            return [cls._normalize_tool_args(tool_name, item) for item in value]
        return value

    @staticmethod
    def _build_repeat_tool_notice(
        tool_name: Any,
        arguments: Dict[str, Any],
        current_tool_call_id: Any,
        previous_calls: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        first = previous_calls[0] if previous_calls else None
        latest = previous_calls[-1] if previous_calls else None
        notice: Dict[str, Any] = {
            "tool": tool_name,
            "arguments": arguments,
            "current_tool_call_id": current_tool_call_id,
            "identical_previous_call_count": len(previous_calls),
            "instruction": (
                "This exact tool call has already appeared in the current conversation. "
                "Read the earlier tool result at the referenced conversation position "
                "instead of requesting the same data again."
            ),
        }
        if first:
            notice["first_seen"] = {
                "iteration": first.get("iteration"),
                "assistant_tool_call_id": first.get("tool_call_id"),
                "assistant_message_index": first.get("assistant_message_index"),
                "tool_result_message_index": first.get("tool_result_message_index"),
            }
        if latest and latest is not first:
            notice["latest_seen"] = {
                "iteration": latest.get("iteration"),
                "assistant_tool_call_id": latest.get("tool_call_id"),
                "assistant_message_index": latest.get("assistant_message_index"),
                "tool_result_message_index": latest.get("tool_result_message_index"),
            }
        return notice

    @classmethod
    def _find_covering_file_snippet_call(
        cls,
        tool_call_history: Dict[str, List[Dict[str, Any]]],
        current_signature: str,
        arguments: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Return a previous get_file_snippet call whose result covers this range."""
        requested_file = cls._normalize_file_path_for_compare(arguments.get("file_path"))
        requested_start = cls._line_number(arguments.get("start_line"))
        requested_end = cls._line_number(arguments.get("end_line"))
        if not requested_file or requested_start is None or requested_end is None:
            return None
        if requested_end < requested_start:
            return None

        for signature, calls in tool_call_history.items():
            if signature == current_signature:
                continue
            for call in reversed(calls):
                if call.get("tool") != "get_file_snippet":
                    continue
                if call.get("blocked") or call.get("cached_replay"):
                    continue
                result = call.get("result")
                if not isinstance(result, dict) or result.get("success") is False:
                    continue
                data = result.get("data")
                if not isinstance(data, dict):
                    continue

                previous_file = cls._normalize_file_path_for_compare(
                    data.get("file") or (call.get("arguments") or {}).get("file_path")
                )
                previous_start = cls._line_number(
                    data.get("start_line") or (call.get("arguments") or {}).get("start_line")
                )
                previous_end = cls._line_number(
                    data.get("end_line") or (call.get("arguments") or {}).get("end_line")
                )
                if (
                    previous_file == requested_file
                    and previous_start is not None
                    and previous_end is not None
                    and previous_start <= requested_start
                    and previous_end >= requested_end
                ):
                    return call
        return None

    @classmethod
    def _build_covered_file_snippet_notice(
        cls,
        arguments: Dict[str, Any],
        current_tool_call_id: Any,
        covering_call: Dict[str, Any],
    ) -> Dict[str, Any]:
        covering_args = covering_call.get("arguments") or {}
        result = (
            covering_call.get("result") if isinstance(covering_call.get("result"), dict) else {}
        )
        data = result.get("data") if isinstance(result, dict) else {}
        if not isinstance(data, dict):
            data = {}
        return {
            "tool": "get_file_snippet",
            "arguments": arguments,
            "current_tool_call_id": current_tool_call_id,
            "covered_by_previous_snippet": {
                "iteration": covering_call.get("iteration"),
                "assistant_tool_call_id": covering_call.get("tool_call_id"),
                "assistant_message_index": covering_call.get("assistant_message_index"),
                "tool_result_message_index": covering_call.get("tool_result_message_index"),
                "file_path": data.get("file") or covering_args.get("file_path"),
                "start_line": data.get("start_line") or covering_args.get("start_line"),
                "end_line": data.get("end_line") or covering_args.get("end_line"),
            },
            "instruction": (
                "The requested file line range is already contained in a previous "
                "get_file_snippet result. This tool message replays that cached "
                "snippet. Use it directly and do not request overlapping snippets "
                "unless the new range includes additional lines that are not present."
            ),
        }

    @classmethod
    def _slice_covering_file_snippet_result(
        cls,
        covering_call: Dict[str, Any],
        arguments: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Derive the exact requested line range from a covering snippet result."""
        result = covering_call.get("result")
        if not isinstance(result, dict) or result.get("success") is not True:
            return None
        data = result.get("data")
        if not isinstance(data, dict):
            return None

        covering_start = cls._line_number(data.get("start_line"))
        covering_end = cls._line_number(data.get("end_line"))
        requested_start = cls._line_number(arguments.get("start_line"))
        requested_end = cls._line_number(arguments.get("end_line"))
        code = data.get("code")
        if (
            covering_start is None
            or covering_end is None
            or requested_start is None
            or requested_end is None
            or not isinstance(code, str)
            or covering_start > requested_start
            or covering_end < requested_end
        ):
            return None

        code_lines = code.splitlines(keepends=True)
        covering_line_count = covering_end - covering_start + 1
        if len(code_lines) != covering_line_count:
            return None
        start_offset = requested_start - covering_start
        end_offset = requested_end - covering_start + 1
        selected_lines = code_lines[start_offset:end_offset]
        if len(selected_lines) != requested_end - requested_start + 1:
            return None

        sliced_data = dict(data)
        sliced_data.update(
            {
                "start_line": requested_start,
                "end_line": requested_end,
                "code": "".join(selected_lines),
            }
        )
        sliced_result = dict(result)
        sliced_result["data"] = sliced_data
        return sliced_result

    @staticmethod
    def _normalize_file_path_for_compare(value: Any) -> str:
        text = str(value or "").strip().replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        return text

    @staticmethod
    def _line_number(value: Any) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _last_replayable_tool_result(
        previous_calls: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Return the latest successful previous tool result that can be replayed."""
        for call in reversed(previous_calls):
            result = call.get("result")
            if not isinstance(result, dict):
                continue
            if result.get("repeat_call_guard") or result.get("cached_tool_result"):
                continue
            if result.get("success") is False:
                continue
            return result
        return None

    def _parse_tool_args(self, func_args_str: Any) -> Dict[str, Any]:
        """Parse tool arguments, with fallbacks for slightly malformed JSON."""
        if isinstance(func_args_str, dict):
            return cast(Dict[str, Any], func_args_str)
        if func_args_str is None:
            return {}
        try:
            return cast(Dict[str, Any], json.loads(str(func_args_str)))
        except json.JSONDecodeError as exc:
            stripped = func_args_str.strip()
            if not stripped:
                return {}

            try:
                parsed = ast.literal_eval(stripped)
                if isinstance(parsed, dict):
                    logger.warning("Recovered tool arguments via literal_eval.")
                    return cast(Dict[str, Any], parsed)
            except (ValueError, SyntaxError):
                pass

            sanitized = self._sanitize_tool_args(stripped)
            if sanitized != stripped:
                for candidate in (sanitized, self._pythonize_json_literals(sanitized)):
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            logger.warning("Recovered tool arguments via sanitized JSON.")
                            return cast(Dict[str, Any], parsed)
                    except json.JSONDecodeError:
                        try:
                            parsed = ast.literal_eval(candidate)
                            if isinstance(parsed, dict):
                                logger.warning(
                                    "Recovered tool arguments via sanitized literal_eval."
                                )
                                return cast(Dict[str, Any], parsed)
                        except (ValueError, SyntaxError):
                            continue

            pythonized = self._pythonize_json_literals(stripped)
            if pythonized != stripped:
                try:
                    parsed = ast.literal_eval(pythonized)
                    if isinstance(parsed, dict):
                        logger.warning("Recovered tool arguments via pythonized literal_eval.")
                        return cast(Dict[str, Any], parsed)
                except (ValueError, SyntaxError):
                    pass

            for json_candidate in extract_json_blocks(str(func_args_str)):
                if isinstance(json_candidate, dict):
                    logger.warning("Recovered tool arguments from JSON block.")
                    return cast(Dict[str, Any], json_candidate)

            fallback = self._extract_tool_args_fallback(stripped)
            if fallback is not None:
                logger.warning("Recovered tool arguments via heuristic fallback.")
                return fallback

            logger.error(
                "Invalid tool arguments JSON. Raw payload: %s",
                self._truncate_tool_args_for_log(func_args_str),
            )
            raise ValueError(f"Invalid tool arguments JSON: {exc}") from exc

    @staticmethod
    def _truncate_tool_args_for_log(value: Any, limit: int = 500) -> str:
        """Return a safely truncated string for logging invalid tool args."""
        if value is None:
            return "<empty>"
        if not isinstance(value, str):
            value = repr(value)
        if len(value) <= limit:
            return str(value)
        return f"{value[:limit]}…(truncated)"

    @staticmethod
    def _sanitize_tool_args(text: str) -> str:
        """Attempt to normalize JSON-like tool argument strings."""
        sanitized = text.strip()
        sanitized = re.sub(r",\s*([}\]])", r"\1", sanitized)
        sanitized = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*):", r'\1"\2"\3:', sanitized)
        return sanitized

    @staticmethod
    def _pythonize_json_literals(text: str) -> str:
        """Swap JSON literals for Python equivalents for literal_eval."""
        pythonized = re.sub(r"\bnull\b", "None", text, flags=re.IGNORECASE)
        pythonized = re.sub(r"\btrue\b", "True", pythonized, flags=re.IGNORECASE)
        pythonized = re.sub(r"\bfalse\b", "False", pythonized, flags=re.IGNORECASE)
        return pythonized

    @staticmethod
    def _extract_tool_args_fallback(text: str) -> Optional[Dict[str, Any]]:
        """Extract common tool args from malformed JSON-like strings."""
        if not isinstance(text, str) or "file_path" not in text:
            return None

        file_match = re.search(r'"file_path"\s*:\s*"([^"]+)"', text)
        if not file_match:
            file_match = re.search(r"'file_path'\s*:\s*'([^']+)'", text)
        if not file_match:
            return None
        file_path = file_match.group(1)
        has_start_line = re.search(r'["\']start_line["\']\s*:', text) is not None
        has_end_line = re.search(r'["\']end_line["\']\s*:', text) is not None

        def extract_int(key: str) -> Optional[int]:
            direct = re.search(rf'"{key}"\s*:\s*([0-9]+)', text)
            if not direct:
                direct = re.search(rf"'{key}'\s*:\s*([0-9]+)", text)
            if direct:
                return int(direct.group(1))
            token = re.search(rf'"{key}"\s*:\s*([^,\n}}]+)', text)
            if not token:
                token = re.search(rf"'{key}'\s*:\s*([^,\n}}]+)", text)
            if token:
                digits = re.search(r"\d+", token.group(1))
                if digits:
                    return int(digits.group(0))
            return None

        start_line = extract_int("start_line")
        end_line = extract_int("end_line")

        if start_line is None and end_line is None:
            if has_start_line or has_end_line:
                return {"file_path": file_path, "start_line": None, "end_line": None}
            return None
        if start_line is None:
            start_line = end_line
        if end_line is None:
            end_line = start_line

        return {"file_path": file_path, "start_line": start_line, "end_line": end_line}
