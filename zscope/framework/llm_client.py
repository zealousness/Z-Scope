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
import math
import os
import ssl
import statistics
import threading
import time
import shutil
import subprocess
import tempfile
from weakref import WeakKeyDictionary
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

from ..common.cancellation import CancellationError, current_cancellation_token
from .conversation_recorder import (
    ConversationSession,
    complete_session_lifecycle,
    get_conversation_recorder,
)
from .cancellable_http import CancellableHTTPAdapter
from .chat_protocol import (
    ChatChunkDecoder,
    ChatProtocolError,
    ProviderContextError,
    validate_assistant_message,
)
from .context_window import (
    DEFAULT_CONTEXT_WINDOW,
    DEFAULT_MAX_TOKENS,
    ContextWindowExceeded,
    compact_tool_result,
    fit_context,
    validate_context_windows,
)
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
    adaptive_limit: int = 0
    owners: Any = field(default_factory=WeakKeyDictionary)


@dataclass
class _GlobalCapacityState:
    owners: Any = field(default_factory=WeakKeyDictionary)
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

    LOCAL_FD_EXHAUSTION_COOLDOWN_SECONDS = 2.0
    SESSION_POOL_MAXSIZE = 1
    DEFAULT_GLOBAL_MAX_INFLIGHT = 8
    AIMD_SUCCESS_THRESHOLD = 20
    AIMD_DECREASE_FACTOR = 0.5
    TRANSIENT_AUTH_RETRY_LIMIT = 1
    TRANSIENT_AUTH_RETRY_DELAY_SECONDS = 1.0

    def __init__(
        self,
        api_key: str,
        base_url: Union[str, Sequence[str]],
        models: List[str],
        timeout: Optional[float] = 120.0,
        max_retries: int = 2,
        retry_until_available: bool = False,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        base_url_rate_limit_per_minute: Optional[int] = None,
        base_url_max_concurrent_requests: Optional[int] = None,
        global_max_concurrent_requests: int = DEFAULT_GLOBAL_MAX_INFLIGHT,
        supports_structured_output: bool = False,
        token_usage_ledger: Optional[ScanTokenUsageLedger] = None,
        llm_ref: str = "",
        context_window: int = DEFAULT_CONTEXT_WINDOW,
        model_context_windows: Optional[Mapping[str, int]] = None,
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
        self.model_context_windows = validate_context_windows(
            context_window, {} if model_context_windows is None else model_context_windows
        )
        self.context_window = context_window
        self._closed = False
        self._owned_in_flight = 0
        self._request_threads: Dict[int, int] = {}
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
        self._tool_schema_lock = threading.Lock()
        self._portable_tool_schema_only = False
        self._usage_telemetry = _UsageTelemetryState()
        self.session = self._new_session()
        self._thread_local.session = self.session

    @staticmethod
    def _strictest_positive_limit(*limits: int) -> int:
        positive = [int(limit) for limit in limits if int(limit or 0) > 0]
        return min(positive) if positive else 0

    def _shared_global_capacity_state(self, max_concurrent_requests: int) -> _GlobalCapacityState:
        with _ENDPOINT_CAPACITY_CONDITION:
            state = _GLOBAL_CAPACITY_STATE
            state.owners[self] = max_concurrent_requests
            state.hard_max_concurrent_requests = self._strictest_positive_limit(
                *state.owners.values()
            )
            return state

    @classmethod
    def _recompute_endpoint_capacity(cls, state: _EndpointCapacityState) -> None:
        values = list(state.owners.values())
        state.hard_max_concurrent_requests = cls._strictest_positive_limit(*(v[0] for v in values))
        state.rate_limit_per_minute = cls._strictest_positive_limit(*(v[1] for v in values))
        state.max_concurrent_requests = cls._strictest_positive_limit(
            state.hard_max_concurrent_requests, state.adaptive_limit
        )

    def _shared_endpoint_capacity_state(
        self,
        url: str,
        max_concurrent_requests: int,
        rate_limit_per_minute: int = 0,
    ) -> _EndpointCapacityState:
        with _ENDPOINT_CAPACITY_CONDITION:
            now = time.monotonic()
            for key, old in list(_ENDPOINT_CAPACITY_STATES.items()):
                self._prune_endpoint_requests(old, now)
                if not old.owners and not old.in_flight and not old.requests_started:
                    del _ENDPOINT_CAPACITY_STATES[key]
            state = _ENDPOINT_CAPACITY_STATES.setdefault(url, _EndpointCapacityState(url=url))
            state.owners[self] = (max_concurrent_requests, rate_limit_per_minute)
            self._recompute_endpoint_capacity(state)
            _ENDPOINT_CAPACITY_CONDITION.notify_all()
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
        """Heuristic for projection/estimated usage, never proof of overflow.

        Count the full wire payload (including schemas), but do not equate UTF-8
        bytes with tokens. Unknown compatible endpoints have unknown tokenizers;
        only their actual context rejection authorizes an enforced retry limit.
        """

        # Include complete wire messages: tool-call IDs/names and structured
        # content also consume context, not just text and argument strings.
        rendered_messages = json.dumps(messages, ensure_ascii=False, separators=(",", ":"))
        estimate = cls.estimate_tokens([{"content": rendered_messages}])
        protocol_payload: Dict[str, Any] = {}
        if tools:
            protocol_payload["tools"] = tools
        if response_format:
            protocol_payload["response_format"] = response_format
        if protocol_payload:
            rendered = json.dumps(protocol_payload, ensure_ascii=False, separators=(",", ":"))
            estimate += cls.estimate_tokens([{"content": rendered}])
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
    def _normalized_provider_usage(
        cls,
        value: Any,
        *,
        estimated_prompt_tokens: int = 0,
        estimated_completion_tokens: int = 0,
    ) -> Dict[str, Any]:
        """Normalize OpenAI-compatible usage variants without retaining content."""

        if not isinstance(value, Mapping):
            return {}

        def first_number(*values: Any) -> Optional[int]:
            for candidate in values:
                if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
                    continue
                if isinstance(candidate, float) and not math.isfinite(candidate):
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
        estimated = prompt is None or completion is None
        prompt = estimated_prompt_tokens if prompt is None else prompt
        completion = estimated_completion_tokens if completion is None else completion
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
            "estimated": estimated,
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
        adapter = CancellableHTTPAdapter(
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
        with self._base_url_condition:
            if self._closed and not self._request_threads.get(threading.get_ident()):
                raise RuntimeError("LLM client is closed")
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
        """Stop admission; active requests retain sessions until they release."""
        with self._base_url_condition:
            if self._closed:
                return
            self._closed = True
            self._global_capacity_state.owners.pop(self, None)
            self._global_capacity_state.hard_max_concurrent_requests = (
                self._strictest_positive_limit(*self._global_capacity_state.owners.values())
            )
            for endpoint in self._endpoint_capacity_states.values():
                endpoint.owners.pop(self, None)
                self._recompute_endpoint_capacity(endpoint)
            self._base_url_condition.notify_all()
            if self._owned_in_flight:
                return
        self._close_sessions()

    def _close_sessions(self) -> None:
        """Called only after admission stopped and this owner's requests drained."""
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
                if self._closed:
                    raise RuntimeError("LLM client is closed")
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
                    self._owned_in_flight += 1
                    thread = threading.get_ident()
                    self._request_threads[thread] = self._request_threads.get(thread, 0) + 1
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
            self._owned_in_flight = max(0, self._owned_in_flight - 1)
            thread = threading.get_ident()
            if self._request_threads.get(thread, 0) <= 1:
                self._request_threads.pop(thread, None)
            else:
                self._request_threads[thread] -= 1
            drained = self._closed and not self._owned_in_flight
            self._base_url_condition.notify_all()
        if drained:
            self._close_sessions()

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
            endpoint.adaptive_limit = (
                endpoint.max_concurrent_requests
                if endpoint.max_concurrent_requests < hard_limit
                else 0
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
                endpoint.adaptive_limit = 1
                endpoint.max_concurrent_requests = 1
                endpoint.success_streak = 0
                endpoint.overload_events += 1
                return
            reduced_limit = max(
                2,
                int(current_limit * self.AIMD_DECREASE_FACTOR),
            )
            endpoint.max_concurrent_requests = min(current_limit, reduced_limit)
            endpoint.adaptive_limit = endpoint.max_concurrent_requests
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
            return max(0.0, float(retry_at.timestamp() - time.time()))
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
        if isinstance(error, ChatProtocolError):
            return None
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

    # ------------------------------------------------------------------
    # HTTP 4xx wire-shape diagnostics. Customer gateways validate payloads
    # with different strictness than the local benchmark replay, so a 400
    # must be diagnosable from logs alone. These helpers never log message
    # contents; they only summarize protocol fields and JSON-Schema
    # constructs that strict providers are known to reject.
    # ------------------------------------------------------------------

    _MESSAGE_STANDARD_KEYS = frozenset(
        {"role", "content", "tool_calls", "tool_call_id", "name", "reasoning_content"}
    )

    @classmethod
    def _collect_json_schema_flags(
        cls,
        node: Any,
        flags: Dict[str, int],
        depth: int = 0,
    ) -> None:
        """Count JSON-Schema constructs that strict provider validators reject."""
        if depth > 16 or not isinstance(node, dict):
            return
        if isinstance(node.get("type"), list):
            flags["type_union"] = flags.get("type_union", 0) + 1
        for keyword in (
            "$defs",
            "$ref",
            "$schema",
            "oneOf",
            "anyOf",
            "allOf",
            "pattern",
            "patternProperties",
            "format",
            "minLength",
            "maxLength",
            "minItems",
            "maxItems",
            "exclusiveMinimum",
            "exclusiveMaximum",
        ):
            if keyword in node:
                flags[keyword] = flags.get(keyword, 0) + 1
        if node.get("additionalProperties") is False:
            flags["additionalProperties_false"] = flags.get("additionalProperties_false", 0) + 1
        for key, value in node.items():
            if key in ("properties", "$defs", "patternProperties") and isinstance(value, dict):
                for child in value.values():
                    cls._collect_json_schema_flags(child, flags, depth + 1)
            elif key in ("items", "additionalProperties", "not", "if", "then", "else"):
                cls._collect_json_schema_flags(value, flags, depth + 1)
            elif key in ("oneOf", "anyOf", "allOf", "prefixItems") and isinstance(value, list):
                for child in value:
                    cls._collect_json_schema_flags(child, flags, depth + 1)

    def _log_http_4xx_diagnostics(
        self,
        *,
        model: str,
        base_url: str,
        status: int,
        response_body: Any,
        payload: Dict[str, Any],
    ) -> None:
        """Log a compact, content-free wire-shape summary of a rejected request.

        Emitted on every HTTP 4xx (including every provider validator 400) so
        the offending protocol field can be identified from customer-environment
        logs: exact top-level payload fields, ``max_tokens``, the ``tool_choice``
        form, ``response_format`` detail, per-role message counts, whether any
        assistant message would replay ``reasoning_content``, unexpected message
        keys, tool names, a tools-schema hash, and JSON-Schema feature flags.
        Never raises; diagnostics must not mask the original failure.
        """
        try:
            messages = payload.get("messages")
            roles: List[str] = []
            role_counts: Dict[str, int] = {}
            extra_message_keys: set = set()
            assistant_with_reasoning = 0
            if isinstance(messages, list):
                for message in messages:
                    if not isinstance(message, dict):
                        roles.append("<non-dict>")
                        continue
                    role = str(message.get("role") or "<missing>")
                    roles.append(role)
                    role_counts[role] = role_counts.get(role, 0) + 1
                    if role == "assistant" and message.get("reasoning_content") is not None:
                        assistant_with_reasoning += 1
                    extra_message_keys.update(
                        str(key) for key in message.keys() if key not in self._MESSAGE_STANDARD_KEYS
                    )
            tools = payload.get("tools")
            tool_names: List[str] = []
            schema_flags: Dict[str, int] = {}
            if isinstance(tools, list):
                for tool in tools:
                    function = tool.get("function") if isinstance(tool, dict) else None
                    name = function.get("name") if isinstance(function, dict) else None
                    tool_names.append(str(name) if name else "<missing>")
                    parameters = function.get("parameters") if isinstance(function, dict) else None
                    self._collect_json_schema_flags(parameters, schema_flags)
            response_format = payload.get("response_format")
            response_format_summary: Any = None
            if isinstance(response_format, dict):
                response_format_summary = {"type": response_format.get("type")}
                json_schema = response_format.get("json_schema")
                if isinstance(json_schema, dict):
                    response_format_summary["json_schema.name"] = json_schema.get("name")
                    response_format_summary["json_schema.strict"] = json_schema.get("strict")
            diag = {
                "model": model,
                "base_url": base_url,
                "status": status,
                "payload_fields": sorted(str(key) for key in payload.keys()),
                "max_tokens": payload.get("max_tokens"),
                "temperature": payload.get("temperature"),
                "tool_choice": payload.get("tool_choice"),
                "response_format": response_format_summary,
                "message_count": len(roles),
                "role_counts": role_counts,
                "role_tail": roles[-6:],
                "assistant_with_reasoning_content": assistant_with_reasoning,
                "message_extra_keys": sorted(extra_message_keys),
                "tool_names": tool_names,
                "tools_schema_hash": self._tools_schema_hash(
                    tools if isinstance(tools, list) else None
                ),
                "tool_schema_flags": schema_flags,
                "stream": payload.get("stream"),
                "stream_options": payload.get("stream_options"),
            }
            logger.warning(
                "[LLM-4xx-DIAG] %s",
                json.dumps(diag, ensure_ascii=False, default=str),
            )
            logger.warning(
                "[LLM-4xx-DIAG] provider_error: %s",
                self._provider_error_summary(status, response_body),
            )
        except Exception:
            logger.warning("[LLM-4xx-DIAG] failed to summarize rejected payload", exc_info=True)

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

    @classmethod
    def _strict_tool_schemas(cls, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create OpenAI strict schemas while retaining nullable optional fields."""

        def strict_value(schema: Any, *, optional: bool = False) -> Any:
            if not isinstance(schema, dict):
                return schema
            result = dict(schema)
            properties = result.get("properties")
            if isinstance(properties, dict):
                originally_required = set(result.get("required") or [])
                result["properties"] = {
                    name: strict_value(value, optional=name not in originally_required)
                    for name, value in properties.items()
                }
                result["required"] = list(properties)
                result["additionalProperties"] = False
            if isinstance(result.get("items"), dict):
                result["items"] = strict_value(result["items"])
            for keyword in ("oneOf", "anyOf"):
                variants = result.get(keyword)
                if isinstance(variants, list):
                    result[keyword] = [strict_value(variant) for variant in variants]
            definitions = result.get("$defs")
            if isinstance(definitions, dict):
                result["$defs"] = {
                    name: strict_value(definition) for name, definition in definitions.items()
                }
            if optional:
                schema_type = result.get("type")
                if schema_type is None or any(key in result for key in ("oneOf", "anyOf", "const")):
                    # Keep every original restriction on the non-null branch.
                    # Replacing an existing union silently accepts arbitrary values.
                    return {"anyOf": [result, {"type": "null"}]}
                if isinstance(schema_type, str):
                    result["type"] = [schema_type, "null"]
                elif isinstance(schema_type, list) and "null" not in schema_type:
                    result["type"] = [*schema_type, "null"]
                if isinstance(result.get("enum"), list) and None not in result["enum"]:
                    result["enum"] = [*result["enum"], None]
            return result

        strict_tools: List[Dict[str, Any]] = []
        for tool in tools:
            copied = json.loads(json.dumps(tool))
            function = copied.get("function")
            if isinstance(function, dict):
                function["parameters"] = strict_value(function.get("parameters") or {})
                function["strict"] = True
            strict_tools.append(copied)
        return strict_tools

    @staticmethod
    def _is_tool_schema_rejection(response_text: str) -> bool:
        lowered = str(response_text or "").lower()
        return any(
            marker in lowered
            for marker in (
                "strict",
                "tool schema",
                "function schema",
                "invalid schema",
                "additionalproperties",
            )
        ) or (
            "required" in lowered
            and any(marker in lowered for marker in ("schema", "function", "tool"))
        )

    @classmethod
    def _provider_error_summary(cls, status: int, body: Any) -> str:
        """Classify rejected responses without persisting provider-echoed secrets."""

        lowered = str(body or "").lower()
        if status in {401, 403}:
            category = "authentication or authorization rejected"
        elif status == 429:
            category = "rate limited"
        elif cls._is_tool_schema_rejection(lowered):
            category = "tool schema rejected"
        elif any(
            value in lowered for value in ("context_length", "context length", "context window")
        ):
            category = "context length exceeded"
        elif "max_tokens" in lowered:
            category = "max_tokens rejected"
        elif status >= 500:
            category = "provider server error"
        else:
            category = "request rejected"
        return f"HTTP {status}: {category}"

    @complete_session_lifecycle
    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        response_format: Optional[Dict[str, Any]] = None,
        thinking: Optional[Dict[str, Any]] = None,
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
        last_context_error: Optional[ContextWindowExceeded] = None
        original_messages = messages
        recorder = get_conversation_recorder()
        created_trace_session = False
        if recorder and trace_session is None:
            trace_session = recorder.begin_session(
                trace_agent or "direct_chat",
                trace_label,
                tools_schema_hash=self._tools_schema_hash(tools),
            )
            created_trace_session = True

        portable_tools = tools
        with self._tool_schema_lock:
            portable_only = self._portable_tool_schema_only
        strict_tools_active = bool(self.supports_structured_output and tools and not portable_only)
        strict_fallback_used = False
        request_tool_schemas = (
            self._strict_tool_schemas(tools) if strict_tools_active and tools else tools
        )

        for model in self.models:
            logger.info(f"Using model: {model}")

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens or self.max_tokens,
            }

            if request_tool_schemas:
                payload["tools"] = request_tool_schemas
                payload["tool_choice"] = tool_choice if tool_choice is not None else "auto"
            if response_format:
                payload["response_format"] = response_format
            if thinking:
                # Some OpenAI-compatible reasoning providers expose a
                # request-local thinking switch.  It is intentionally not a
                # public profile default: callers use it only for bounded
                # mechanical formatting/repair calls where another long
                # hidden chain of thought can consume the entire output
                # allowance before the required terminal JSON is emitted.
                payload["thinking"] = dict(thinking)

            # Force streaming to bypass middle-proxy timeouts (e.g. 504 on 120s limit)
            payload["stream"] = True
            # OpenAI-compatible streaming APIs only include the terminal usage
            # chunk when explicitly requested.  Provider-reported usage is a
            # formal benchmark invariant; incompatible endpoints remain
            # visible as estimated telemetry instead of being misclassified.
            payload["stream_options"] = {"include_usage": True}

            total_attempts = (self.max_retries + 1) * max(1, len(self._base_url_states))
            attempt = 0
            context_prompt_limit: Optional[int] = None
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
                try:
                    messages = self._prepare_messages_for_model(
                        original_messages,
                        model=model,
                        tools=request_tool_schemas,
                        response_format=response_format,
                        max_tokens=max_tokens,
                        preserve_reasoning_metadata=True,
                        input_limit=context_prompt_limit,
                    )
                except ContextWindowExceeded as exc:
                    last_context_error = exc
                    last_error = str(exc)
                    self._record_control_event(
                        trace_session,
                        trace_iteration or 0,
                        "context_window_exceeded",
                        {"model": model, "error": str(exc)},
                    )
                    break  # A larger fallback model may fit the same required evidence.
                payload["messages"] = messages
                if messages != original_messages:
                    self._record_control_event(
                        trace_session,
                        trace_iteration or 0,
                        "context_compaction",
                        {
                            "model": model,
                            "context_window": self.model_context_windows.get(
                                model, self.context_window
                            ),
                            "estimated_prompt_tokens": self._estimate_request_prompt_tokens(
                                messages,
                                tools=request_tool_schemas,
                                response_format=response_format,
                            ),
                        },
                    )
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
                        tools=request_tool_schemas,
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
                        prompt_tokens = self._estimate_request_prompt_tokens(
                            messages, tools=request_tool_schemas, response_format=response_format
                        )
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        usage: Dict[str, Any] = {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                            "estimated": True,
                        }
                        normalized_provider_usage = self._normalized_provider_usage(
                            provider_usage,
                            estimated_prompt_tokens=prompt_tokens,
                            estimated_completion_tokens=completion_tokens,
                        )
                        if normalized_provider_usage:
                            usage.update(normalized_provider_usage)
                        prompt_tokens = usage["prompt_tokens"]
                        completion_tokens = usage["completion_tokens"]
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
                        url,
                        json=cast(Any, attempt_payload),
                        timeout=request_timeout,
                        stream=True,
                    )

                    if response.status_code == 200:
                        assembled_message, finish_reason, provider_usage = (
                            self._assemble_chat_response_with_usage(response)
                        )

                        # Estimate single API call cost and log prominently
                        prompt_tokens = self._estimate_request_prompt_tokens(
                            messages, tools=request_tool_schemas, response_format=response_format
                        )
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        usage = {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                            "estimated": True,
                        }
                        normalized_provider_usage = self._normalized_provider_usage(
                            provider_usage,
                            estimated_prompt_tokens=prompt_tokens,
                            estimated_completion_tokens=completion_tokens,
                        )
                        if normalized_provider_usage:
                            usage.update(normalized_provider_usage)
                        prompt_tokens = usage["prompt_tokens"]
                        completion_tokens = usage["completion_tokens"]
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

                    error_msg = self._provider_error_summary(response.status_code, response.text)
                    if (
                        response.status_code == 400
                        and error_msg == "HTTP 400: context length exceeded"
                    ):
                        raise ProviderContextError(error_msg)
                    transient_http_error = (
                        response.status_code >= 500 or response.status_code == 429
                    )
                    if 400 <= response.status_code < 500:
                        self._log_http_4xx_diagnostics(
                            model=model,
                            base_url=endpoint.url,
                            status=response.status_code,
                            response_body=response.text,
                            payload=attempt_payload,
                        )
                    if (
                        response.status_code == 400
                        and strict_tools_active
                        and not strict_fallback_used
                        and self._is_tool_schema_rejection(response.text)
                    ):
                        strict_fallback_used = True
                        strict_tools_active = False
                        with self._tool_schema_lock:
                            self._portable_tool_schema_only = True
                        total_attempts += 1
                        request_tool_schemas = portable_tools
                        payload["tools"] = portable_tools
                        last_error = error_msg
                        logger.warning(
                            "tool_schema_strict_fallback model=%s endpoint=%s",
                            model,
                            endpoint.url,
                        )
                        self._record_control_event(
                            trace_session,
                            trace_iteration or 0,
                            "tool_schema_strict_fallback",
                            {"model": model, "base_url": endpoint.url},
                        )
                        continue
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

                except CancellationError:
                    raise
                except Exception as e:
                    if token is not None:
                        token.raise_if_cancelled()
                    if isinstance(e, ProviderContextError):
                        prompt_size = self._estimate_request_prompt_tokens(
                            messages, tools=request_tool_schemas, response_format=response_format
                        )
                        if context_prompt_limit is None:
                            context_prompt_limit = max(1, prompt_size // 2)
                            total_attempts += 1
                            self._record_control_event(
                                trace_session,
                                trace_iteration or 0,
                                "provider_context_retry",
                                {"model": model, "input_limit": context_prompt_limit},
                            )
                            last_error = str(e)
                            continue
                        window = self.model_context_windows.get(model, self.context_window)
                        last_context_error = ContextWindowExceeded(
                            window=window,
                            prompt_tokens=prompt_size,
                            output_tokens=max_tokens or self.max_tokens,
                            margin=max(256, (window + 19) // 20),
                            input_limit=context_prompt_limit,
                            provider_rejected=True,
                        )
                        last_error = str(last_context_error)
                        break
                    exception_text = str(e)
                    if (
                        exception_text.startswith("HTTP 400:")
                        and strict_tools_active
                        and not strict_fallback_used
                        and self._is_tool_schema_rejection(exception_text)
                    ):
                        strict_fallback_used = True
                        strict_tools_active = False
                        with self._tool_schema_lock:
                            self._portable_tool_schema_only = True
                        total_attempts += 1
                        request_tool_schemas = portable_tools
                        payload["tools"] = portable_tools
                        last_error = exception_text
                        logger.warning(
                            "tool_schema_strict_fallback model=%s endpoint=%s",
                            model,
                            endpoint.url,
                        )
                        self._record_control_event(
                            trace_session,
                            trace_iteration or 0,
                            "tool_schema_strict_fallback",
                            {"model": model, "base_url": endpoint.url},
                        )
                        continue
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

        if last_context_error is not None and last_error == str(last_context_error):
            raise last_context_error
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
            with subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                pending_input: Optional[bytes] = request_bytes
                try:
                    while True:
                        if token is not None:
                            token.raise_if_cancelled()
                        try:
                            stdout_bytes, _stderr_bytes = proc.communicate(
                                input=pending_input, timeout=0.2
                            )
                            break
                        except subprocess.TimeoutExpired:
                            # communicate retains partially written stdin and
                            # collected output; only supply input on its first call.
                            pending_input = None
                    if token is not None:
                        token.raise_if_cancelled()
                except BaseException:
                    if proc.poll() is None:
                        proc.kill()
                    proc.communicate()
                    raise
                returncode = proc.returncode
        finally:
            try:
                os.unlink(config_path)
            except OSError:
                logger.debug("Failed to remove temporary curl config", exc_info=True)
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        if status_marker not in stdout:
            raise RuntimeError(f"curl transport did not return an HTTP status (exit {returncode})")
        body, raw_status = stdout.rsplit(status_marker, 1)
        try:
            status = int(raw_status.strip()[-3:])
        except ValueError as exc:
            raise RuntimeError("curl transport returned invalid HTTP status") from exc
        if returncode != 0:
            raise RuntimeError(f"curl transport failed (exit {returncode})")
        if status != 200:
            summary = self._provider_error_summary(status, body)
            if status == 400 and summary == "HTTP 400: context length exceeded":
                raise ProviderContextError(summary)
            if 400 <= status < 500:
                # curl_payload has stream_options stripped and stream=False, so
                # the summary reflects the curl-transport wire shape.
                self._log_http_4xx_diagnostics(
                    model=str(payload.get("model") or ""),
                    base_url=url,
                    status=status,
                    response_body=body,
                    payload=curl_payload,
                )
            raise RuntimeError(self._provider_error_summary(status, body))
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("curl transport returned non-JSON response") from exc
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("curl transport response missing choices")
        choice = choices[0] if isinstance(choices[0], dict) else {}
        message = choice.get("message") or {}
        if not isinstance(message, dict):
            message = {"role": "assistant", "content": str(message)}
        message.setdefault("role", "assistant")
        message.setdefault("content", "")
        finish_reason = choice.get("finish_reason")
        validate_assistant_message(message, finish_reason)
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return message, str(finish_reason), dict(usage)

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
        saw_finish_reason = False
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
            if "error" in chunk:
                raise requests.exceptions.ChunkedEncodingError("Provider stream returned an error")
            chunk_usage = chunk.get("usage")
            if isinstance(chunk_usage, dict):
                provider_usage.update(chunk_usage)
            choices = chunk.get("choices", [])
            if not choices:
                continue
            if saw_finish_reason:
                raise ChatProtocolError("Chat content arrived after the completed turn")

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
                saw_finish_reason = True

        if not saw_finish_reason:
            raise requests.exceptions.ChunkedEncodingError(
                "Chat completion stream ended without a finish_reason (stream truncated)"
            )

        assembled_message: Dict[str, Any] = {"role": "assistant"}
        if content_pieces:
            assembled_message["content"] = "".join(content_pieces)
        if tool_calls_map:
            assembled_message["tool_calls"] = [
                {field: value for field, value in tool_calls_map[key].items() if field != "index"}
                for key in sorted(tool_calls_map.keys())
            ]
            assembled_message.setdefault("content", "")
        else:
            assembled_message.setdefault("content", "")
        if reasoning_pieces:
            assembled_message["reasoning_content"] = "".join(reasoning_pieces)

        validate_assistant_message(assembled_message, finish_reason)
        return assembled_message, finish_reason, provider_usage

    @staticmethod
    def _iter_chat_chunks(
        response: requests.Response,
        *,
        max_stream_seconds: Optional[float] = None,
        max_idle_valid_chunk_seconds: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        if "application/json" in getattr(response, "headers", {}).get("Content-Type", ""):
            data = response.json()
            if not isinstance(data, dict):
                raise requests.exceptions.ChunkedEncodingError("Invalid chat JSON response")
            yield data
            return
        decoder = ChatChunkDecoder()
        stream_started_at = time.monotonic()
        last_valid_chunk_at = stream_started_at
        for line in response.iter_lines():
            token = current_cancellation_token()
            if token is not None:
                token.raise_if_cancelled()
            now = time.monotonic()
            if max_stream_seconds is not None and now - stream_started_at > max_stream_seconds:
                raise TimeoutError(f"Chat completion stream exceeded {max_stream_seconds:.0f}s")
            if (
                max_idle_valid_chunk_seconds is not None
                and now - last_valid_chunk_at > max_idle_valid_chunk_seconds
            ):
                raise TimeoutError(
                    "Chat completion stream did not yield a valid JSON chunk "
                    f"for {max_idle_valid_chunk_seconds:.0f}s"
                )
            decoded_line = line.decode("utf-8") if isinstance(line, bytes) else str(line)
            chunk = decoder.feed(decoded_line)
            if chunk is not None:
                last_valid_chunk_at = time.monotonic()
                yield chunk
            if decoder.done:
                return
        decoder.finish()

    @staticmethod
    def _merge_tool_call(
        tool_calls_map: Dict[Any, Dict[str, Any]],
        tool_call: Dict[str, Any],
        fallback_index: int,
    ) -> None:
        idx = tool_call.get("index", fallback_index)
        if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0:
            raise requests.exceptions.ChunkedEncodingError("Invalid streamed tool call index")
        existing = tool_calls_map.setdefault(idx, {})

        if tool_call.get("type") is not None:
            existing["type"] = tool_call["type"]
        if tool_call.get("id") is not None:
            existing["id"] = str(existing.get("id", "")) + str(tool_call["id"])

        function_delta = tool_call.get("function")
        if isinstance(function_delta, dict):
            function = existing.setdefault("function", {})
            if function_delta.get("name"):
                function["name"] = str(function.get("name", "")) + str(function_delta["name"])
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

    # Code points whose characters tokenize at roughly one token per 1-1.5
    # characters on mainstream BPE tokenizers, versus ~3.8 chars/token for
    # ASCII-heavy text.  CJK is counted separately so the estimate does not
    # silently undercount context size for Chinese-heavy prompts.
    _CJK_TOKEN_CHARS_PER_TOKEN = 1.5
    _ASCII_TOKEN_CHARS_PER_TOKEN = 3.8
    _CJK_CHAR_RE = re.compile(
        "[\u3000-\u303f\u3040-\u30ff\u3130-\u318f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]"
    )

    @classmethod
    def estimate_tokens(cls, conversation: List[Dict[str, Any]]) -> int:
        """Estimate the total token count of a conversation.

        Uses a simple heuristic: ~1.5 chars per token for CJK characters and
        ~3.8 chars per token for the rest. This avoids a tiktoken dependency.
        """
        cjk_chars = 0
        other_chars = 0
        for msg in conversation:
            content = msg.get("content") or ""
            if isinstance(content, str):
                cjk_chars += len(cls._CJK_CHAR_RE.findall(content))
                other_chars += len(content)
            # Count tool call arguments as part of the context
            for tc in msg.get("tool_calls", []):
                args = tc.get("function", {}).get("arguments", "")
                if isinstance(args, str):
                    cjk_chars += len(cls._CJK_CHAR_RE.findall(args))
                    other_chars += len(args)
            # Count reasoning_content if present (e.g. DeepSeek R1)
            rc = msg.get("reasoning_content") or ""
            if isinstance(rc, str):
                cjk_chars += len(cls._CJK_CHAR_RE.findall(rc))
                other_chars += len(rc)
        other_chars -= cjk_chars
        estimate = cjk_chars / cls._CJK_TOKEN_CHARS_PER_TOKEN + (
            other_chars / cls._ASCII_TOKEN_CHARS_PER_TOKEN
        )
        return int(estimate)

    def _prepare_messages_for_model(
        self,
        conversation: List[Dict[str, Any]],
        *,
        model: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        response_format: Optional[Dict[str, Any]] = None,
        max_tokens: Optional[int] = None,
        preserve_reasoning_metadata: bool = True,
        preserve_latest_reasoning_metadata: bool = False,
        input_limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        projected = self._project_messages_for_model(
            conversation,
            preserve_reasoning_metadata=preserve_reasoning_metadata,
            preserve_latest_reasoning_metadata=preserve_latest_reasoning_metadata,
        )
        selected_model = model or (self.models[0] if self.models else "")
        window = self.model_context_windows.get(selected_model, self.context_window)
        fitted = fit_context(
            projected,
            window=window,
            output_tokens=max_tokens or self.max_tokens,
            estimate=lambda rows: self._estimate_request_prompt_tokens(
                rows, tools=tools, response_format=response_format
            ),
            input_limit=input_limit,
        )
        if fitted != projected:
            logger.info("Projected tool text to fit model context window=%d", window)
        return fitted

    def _project_messages_for_model(
        self,
        conversation: List[Dict[str, Any]],
        *,
        preserve_reasoning_metadata: bool = True,
        preserve_latest_reasoning_metadata: bool = False,
    ) -> List[Dict[str, Any]]:
        """Apply provider reasoning policy without changing the authoritative transcript.

        Window enforcement runs at the HTTP boundary, against the selected model
        and actual wire schemas (including strict conversion and model fallback).
        """
        latest_assistant_index = next(
            (
                i
                for i in range(len(conversation) - 1, -1, -1)
                if conversation[i].get("role") == "assistant"
            ),
            None,
        )
        projected = []
        for index, message in enumerate(conversation):
            copied = self._copy_message_for_model(message)
            if (
                message.get("role") == "assistant"
                and not preserve_reasoning_metadata
                and not (preserve_latest_reasoning_metadata and index == latest_assistant_index)
            ):
                copied.pop("reasoning_content", None)
            projected.append(copied)
        return projected

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
        return compact_tool_result(content, tool_call_id)

    @staticmethod
    def _truncate_text(value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        omitted = len(value) - limit
        head = max(0, limit - 48)
        return f"{value[:head]}...[truncated {omitted} chars]"

    @complete_session_lifecycle
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
        preserve_reasoning_metadata: bool = True,
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
        context_window_error: Optional[str] = None
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
                cumulative_total_tokens=cumulative_prompt_tokens + cumulative_completion_tokens,
                wall_seconds=max(0.0, time.monotonic() - conversation_started_monotonic),
                finish_reason=finish_reason_value,
                loop_guard_triggered=loop_guard_fired or None,
                terminal_tool_valid=terminal_valid,
            )

        while iterations < max_iterations:
            token = current_cancellation_token()
            if token is not None:
                token.raise_if_cancelled()
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
                self._record_control_event(trace_session, iterations, "forced_final_by_executor")
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

            model_conversation = self._project_messages_for_model(
                conversation,
                preserve_reasoning_metadata=preserve_reasoning_metadata,
                preserve_latest_reasoning_metadata=last_finish_reason == "length",
            )
            ctx_tokens = self.estimate_tokens(model_conversation)
            raw_ctx_tokens = self.estimate_tokens(conversation)
            logger.info(
                "Conversation iteration %s/%s | pre-window context ≈%s tokens (raw ≈%s)",
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
            try:
                response = self.chat_completion(model_conversation, **completion_kwargs)
            except ContextWindowExceeded as exc:
                # Keep all collected evidence and paired messages for the owner;
                # this is an incomplete investigation, never a terminal verdict.
                last_finish_reason = "context_window_exceeded"
                context_window_error = str(exc)
                break

            # Extract assistant message
            choice = response.get("choices", [{}])[0]
            message = choice.get("message", {})
            finish_reason = choice.get("finish_reason")
            validate_assistant_message(message, finish_reason)
            if token is not None:
                token.raise_if_cancelled()
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
            if finish_reason == "stop" and not message.get("tool_calls"):
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
                    self._project_messages_for_model(
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
                if message.get("tool_calls"):
                    # A truncated call is neither executable nor a valid
                    # assistant/tool exchange to replay to a strict provider.
                    # Let the owning agent perform its bounded output repair.
                    self._record_control_event(
                        trace_session,
                        iterations,
                        "truncated_tool_call",
                        {"finish_reason": "length"},
                    )
                    break
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
                    self._project_messages_for_model(
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

            # Text, including quoted XML examples, is never an executable
            # protocol envelope. Compatible providers must emit tool_calls.

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
                    self._project_messages_for_model(
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
                    if token is not None:
                        token.raise_if_cancelled()
                    terminal_id = terminal_call.get("id")
                    terminal_function = terminal_call.get("function", {})
                    raw_terminal_args = terminal_function.get("arguments", "{}")
                    try:
                        terminal_args = self._parse_tool_args(raw_terminal_args)
                        terminal_args = self._restore_portable_tool_args(
                            str(terminal_tool_name), terminal_args, tools_schema
                        )
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
                        except CancellationError:
                            raise
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
                            self._project_messages_for_model(
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
                            self._project_messages_for_model(
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
                if token is not None:
                    token.raise_if_cancelled()
                tool_id = tool_call.get("id")
                function = tool_call.get("function", {})
                func_name = function.get("name")
                func_args_str = function.get("arguments", "{}")

                logger.info(f"Tool call: {func_name}")

                tool_started = time.monotonic()
                func_args: Dict[str, Any] = {}
                try:
                    func_args = self._parse_tool_args(func_args_str)
                    func_args = self._restore_portable_tool_args(
                        str(func_name or ""),
                        func_args,
                        tools_schema,
                    )

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
                    else:
                        set_tool_iteration = getattr(tool_executor, "_zscope_set_iteration", None)
                        if callable(set_tool_iteration):
                            set_tool_iteration(iterations)
                        if token is not None:
                            token.raise_if_cancelled()
                        # Only the executor can revalidate source/build/permission
                        # identity. Never replay evidence from the loop's history.
                        result = tool_executor(func_name, func_args)
                        if token is not None:
                            token.raise_if_cancelled()
                        previous_result = (
                            previous_calls[-1].get("result") if previous_calls else None
                        )
                        comparable = (
                            dict(previous_result)
                            if isinstance(previous_result, dict)
                            else previous_result
                        )
                        if isinstance(comparable, dict):
                            comparable.pop("repeat_call_warning", None)
                        if previous_calls and comparable != result:
                            previous_calls = []
                            tool_call_history[signature] = []
                        repeated_call_count = len(previous_calls) + 1
                        if previous_calls and isinstance(result, dict):
                            result = dict(result)
                            result["repeat_call_warning"] = repeat_notice
                        if (
                            max_identical_tool_calls > 0
                            and len(previous_calls) >= max_identical_tool_calls
                        ):
                            result = dict(result)
                            result["repeat_call_guard"] = True
                            result["repeat_call_warning"] = {
                                **repeat_notice,
                                "instruction": "The current result was revalidated. Repeated unchanged calls are now blocked; use other tools or synthesize from current evidence.",
                            }

                    tool_result_message_index = len(conversation) + 1
                    conversation.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_id,
                            # default=str keeps a single non-JSON-native value
                            # (bytes, set, Path) from discarding the whole tool
                            # result and replacing it with an error message.
                            "content": json.dumps(result, ensure_ascii=False, default=str),
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

                except CancellationError:
                    raise
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
                            f"{disabled_names}. Their latest tool messages contain the revalidated "
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
            self._project_messages_for_model(
                conversation,
                preserve_reasoning_metadata=preserve_reasoning_metadata,
            )
        )
        logger.info(
            "Conversation ended (truncated=%s): %s iterations, final context ≈ %s tokens",
            iterations >= max_iterations
            or last_finish_reason in {"length", "context_window_exceeded"},
            iterations,
            f"{final_tokens:,}",
        )
        _record_session_end_traced(
            iterations,
            final_tokens,
            truncated=iterations >= max_iterations
            or last_finish_reason in {"length", "context_window_exceeded"},
            finish_reason_value=last_finish_reason,
            terminal_valid=terminal_tool_valid,
        )
        result_payload = {
            # The loop can exit with a trailing user message ("请继续" length
            # continuation, loop-guard notice, final-iteration instruction),
            # so the last conversation entry is not the model's answer.  Use
            # the same combined-assistant-content projection as the normal
            # completion paths instead of leaking the prompt text as content.
            "content": self._get_combined_content(conversation),
            "conversation": conversation,
            "iterations": iterations,
            "truncated": iterations >= max_iterations
            or last_finish_reason in {"length", "context_window_exceeded"},
            "context_tokens": final_tokens,
            "api_call_count": iterations - int(context_window_error is not None),
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
        if context_window_error is not None:
            result_payload["context_window_error"] = context_window_error
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
    def _normalize_tool_args(cls, tool_name: str, value: Any, *, _root: bool = True) -> Any:
        if isinstance(value, dict):
            normalized = {
                str(key): cls._normalize_tool_args(tool_name, val, _root=False)
                for key, val in value.items()
            }
            if not _root:
                return normalized
            defaults: Dict[str, Dict[str, Any]] = {
                "search_code": {
                    "kinds": None,
                    "match_mode": "substring",
                    "path_prefix": None,
                    "limit": 20,
                    "offset": 0,
                },
                "read_code": {
                    "symbol_id": None,
                    "file_path": None,
                    "start_line": None,
                    "end_line": None,
                    "max_lines": 200,
                },
                "get_semantic_context": {
                    "symbol_id": None,
                    "query": None,
                    "limit": 20,
                    "offset": 0,
                },
                "query_code_graph": {"direction": "both", "depth": 1, "limit": 30, "offset": 0},
                "trace_data_flow": {
                    "max_call_depth": 3,
                    "include_may_alias": True,
                    "limit": 10,
                    "offset": 0,
                },
                "query_static_findings": {
                    "symbol_id": None,
                    "producers": None,
                    "rule_id": None,
                    "category": None,
                    "validation_states": None,
                    "limit": 20,
                    "offset": 0,
                },
            }
            for key, default in defaults.get(tool_name, {}).items():
                normalized.setdefault(key, default)
            if tool_name == "trace_data_flow":
                source = normalized.get("source")
                if isinstance(source, dict):
                    for key in ("name", "file_path", "line", "column"):
                        source.setdefault(key, None)
                sink = normalized.get("sink")
                if isinstance(sink, dict):
                    for key, default in (
                        ("query", None),
                        ("match_mode", "exact"),
                        ("name", None),
                        ("file_path", None),
                        ("line", None),
                        ("column", None),
                    ):
                        sink.setdefault(key, default)
            return normalized
        if isinstance(value, list):
            return [cls._normalize_tool_args(tool_name, item, _root=False) for item in value]
        return value

    @classmethod
    def _restore_portable_tool_args(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        tools_schema: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Remove only nulls introduced by strict nullable-required adaptation.

        The provider sees a strict copy in which every optional property is
        required and nullable. Execution still validates against the original
        portable contract, so an artificial null must become an omitted field.
        Properties that were nullable in the original contract retain null.
        """
        from .base import _validate_json_value

        # Some compatible providers serialize absent opaque IDs as the string
        # "null". Neither ID vocabulary contains that value. Restore absence
        # only when the alternative locator/first-page request is explicit;
        # never rewrite literal search text, file names or continuation IDs.
        if (
            tool_name == "read_code"
            and arguments.get("symbol_id") == "null"
            and arguments.get("file_path")
        ) or (
            tool_name == "search_code"
            and arguments.get("view_id") == "null"
            and arguments.get("offset", 0) == 0
        ):
            arguments = dict(arguments)
            arguments["symbol_id" if tool_name == "read_code" else "view_id"] = None

        parameters: Dict[str, Any] = {}
        for tool in tools_schema:
            function = tool.get("function") if isinstance(tool, dict) else None
            if not isinstance(function, dict) or function.get("name") != tool_name:
                continue
            candidate = function.get("parameters")
            if isinstance(candidate, dict):
                parameters = candidate
            break

        def reference_target(reference: Any) -> Optional[Dict[str, Any]]:
            if not isinstance(reference, str) or not reference.startswith("#/"):
                return None
            target: Any = parameters
            for part in reference[2:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                target = target.get(key) if isinstance(target, dict) else None
            return target if isinstance(target, dict) else None

        def matches(
            value: Any,
            schema: Dict[str, Any],
            seen: frozenset[tuple[int, int]] = frozenset(),
        ) -> bool:
            marker = (id(value), id(schema))
            if marker in seen:
                return False
            seen = seen | {marker}
            if "$ref" in schema:
                target = reference_target(schema["$ref"])
                if target is None or not matches(value, target, seen):
                    return False
            # Reuse the ordinary scalar and object-shape constraints, then
            # validate actual children here so local refs keep their root scope.
            shallow = {key: item for key, item in schema.items() if key not in ("anyOf", "oneOf")}
            properties = schema.get("properties")
            if isinstance(properties, dict):
                shallow["properties"] = {key: {} for key in properties}
            if isinstance(schema.get("items"), dict):
                shallow["items"] = {}
            if _validate_json_value(shallow, value, "") is not None:
                return False
            if isinstance(value, dict) and isinstance(properties, dict):
                for key, item in value.items():
                    child_schema = properties.get(key)
                    if isinstance(child_schema, dict) and not matches(item, child_schema, seen):
                        return False
            if isinstance(value, list) and isinstance(schema.get("items"), dict):
                if any(not matches(item, schema["items"], seen) for item in value):
                    return False
            for keyword in ("anyOf", "oneOf"):
                variants = schema.get(keyword)
                if isinstance(variants, list):
                    count = sum(
                        isinstance(variant, dict) and matches(value, variant, seen)
                        for variant in variants
                    )
                    if count == 0 or keyword == "oneOf" and count != 1:
                        return False
            return True

        def allows_null(schema: Dict[str, Any]) -> bool:
            return matches(None, schema)

        def restore(
            value: Any,
            schema: Dict[str, Any],
            seen: frozenset[tuple[int, int]] = frozenset(),
        ) -> Any:
            marker = (id(value), id(schema))
            if marker in seen:
                return value
            seen = seen | {marker}
            if "$ref" in schema:
                target = reference_target(schema["$ref"])
                if target is not None:
                    value = restore(value, target, seen)
            if isinstance(value, dict):
                properties = schema.get("properties")
                properties = properties if isinstance(properties, dict) else {}
                required = set(schema.get("required") or [])
                result: Dict[str, Any] = {}
                for key, item in value.items():
                    property_schema = properties.get(key)
                    if not isinstance(property_schema, dict):
                        result[key] = item
                        continue
                    if item is None and key not in required and not allows_null(property_schema):
                        continue
                    result[key] = restore(item, property_schema, seen)
                value = result
            elif isinstance(value, list):
                item_schema = schema.get("items")
                if isinstance(item_schema, dict):
                    value = [restore(item, item_schema, seen) for item in value]
            if matches(value, schema):
                return value
            for keyword in ("anyOf", "oneOf"):
                variants = schema.get(keyword)
                if not isinstance(variants, list):
                    continue
                candidates = []
                for variant in variants:
                    if not isinstance(variant, dict):
                        continue
                    candidate = restore(value, variant, seen)
                    if matches(candidate, schema) and candidate not in candidates:
                        candidates.append(candidate)
                # Never guess between branches that remove different fields.
                # Keep the invalid payload for the ordinary validator to explain.
                if len(candidates) == 1:
                    return candidates[0]
            return value

        restored = restore(arguments, parameters)
        return restored if isinstance(restored, dict) else dict(arguments)

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
                "Use the newly validated result; prior results are historical evidence "
                "and may no longer describe current inputs."
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

    def _parse_tool_args(self, func_args_str: Any) -> Dict[str, Any]:
        """Parse tool arguments, with fallbacks for slightly malformed JSON."""

        def checked(value: Dict[str, Any]) -> Dict[str, Any]:
            # Python's JSON decoder accepts NaN/Infinity; they are not JSON
            # arguments and must not enter a tool or its subsequent transcript.
            json.dumps(value, allow_nan=False)
            return value

        if isinstance(func_args_str, dict):
            return checked(func_args_str)
        if func_args_str is None:
            return {}
        if not isinstance(func_args_str, str):
            raise ValueError("Tool arguments must be a JSON object")
        try:
            parsed_json = json.loads(func_args_str)
            if not isinstance(parsed_json, dict):
                raise ValueError("Tool arguments must be a JSON object")
            return checked(parsed_json)
        except json.JSONDecodeError as exc:
            stripped = func_args_str.strip()
            if not stripped:
                return {}

            try:
                parsed = ast.literal_eval(stripped)
                if isinstance(parsed, dict):
                    logger.warning("Recovered tool arguments via literal_eval.")
                    return checked(parsed)
            except (ValueError, SyntaxError):
                pass

            sanitized = self._sanitize_tool_args(stripped)
            if sanitized != stripped:
                for candidate in (sanitized, self._pythonize_json_literals(sanitized)):
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            logger.warning("Recovered tool arguments via sanitized JSON.")
                            return checked(parsed)
                    except json.JSONDecodeError:
                        try:
                            parsed = ast.literal_eval(candidate)
                            if isinstance(parsed, dict):
                                logger.warning(
                                    "Recovered tool arguments via sanitized literal_eval."
                                )
                                return checked(parsed)
                        except (ValueError, SyntaxError):
                            continue

            pythonized = self._pythonize_json_literals(stripped)
            if pythonized != stripped:
                try:
                    parsed = ast.literal_eval(pythonized)
                    if isinstance(parsed, dict):
                        logger.warning("Recovered tool arguments via pythonized literal_eval.")
                        return checked(parsed)
                except (ValueError, SyntaxError):
                    pass

            logger.error("Invalid tool arguments JSON; no lossless repair was available.")
            raise ValueError(f"Invalid tool arguments JSON: {exc}") from exc

    @staticmethod
    def _sanitize_tool_args(text: str) -> str:
        """Attempt to normalize JSON-like tool argument strings."""
        # Match quoted tokens first so syntax repairs never alter source,
        # search queries, paths, or other literal argument values.
        pattern = (
            r"""(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
            r"|(?P<trailing>,\s*(?=[}\]]))"
            r"|(?P<key>(?<=[{,])\s*[A-Za-z_][A-Za-z0-9_]*\s*:)"
        )

        def repair(match: re.Match[str]) -> str:
            if match.group("string") is not None:
                return match.group(0)
            if match.group("trailing") is not None:
                return ""
            return json.dumps(match.group("key")[:-1].strip()) + ":"

        return re.sub(pattern, repair, text.strip())

    @staticmethod
    def _pythonize_json_literals(text: str) -> str:
        """Swap JSON literals for Python equivalents for literal_eval."""
        pattern = (
            r"""(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
            r"|(?P<literal>\b(?:null|true|false)\b)"
        )
        replacements = {"null": "None", "true": "True", "false": "False"}
        return re.sub(
            pattern,
            lambda match: (
                match.group(0)
                if match.group("string") is not None
                else replacements[match.group("literal").lower()]
            ),
            text,
            flags=re.IGNORECASE,
        )
