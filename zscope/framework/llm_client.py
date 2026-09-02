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
    P6_BALANCED_PROMPT_ACCOUNTING_HEADROOM,
    P6BalancedTokenAdmissionError,
    ScanTokenUsageLedger,
    TokenUsageReservation,
    current_llm_usage_attribution,
)

logger = logging.getLogger(__name__)


# P6 admission must be conservative without depending on a provider-specific
# tokenizer.  OpenAI-compatible tokenizers cannot consume more tokens than
# the UTF-8 byte stream they tokenize (byte fallback is the worst case).  The
# frozen allowance covers provider chat-template sentinels which are not part
# of the JSON request itself.  These constants are deliberately generous: the
# admission contract prefers stopping early to crossing the 11,999,999-token
# selected-attempt ceiling.
_REQUEST_PROMPT_TEMPLATE_BASE_ALLOWANCE = P6_BALANCED_PROMPT_ACCOUNTING_HEADROOM // 8
_REQUEST_PROMPT_TEMPLATE_PER_ITEM_ALLOWANCE = 256


PROVIDER_FAILURE_CLASSES = frozenset(
    {
        "provider_credentials_unavailable",
        "provider_transport_exhausted",
        "provider_usage_unverifiable",
        "provider_identity_mismatch",
        "provider_protocol_incompatible",
    }
)


class ProviderFailureError(RuntimeError):
    """Public, body-free provider failure for control-plane classification.

    ``failure_class`` is the only diagnostic detail exposed by this exception.
    The message is deliberately constant so logging the exception cannot retain
    an endpoint, HTTP status, provider body, model output, or credential.
    """

    MESSAGE = "provider request failed"

    def __init__(self, failure_class: str) -> None:
        if failure_class not in PROVIDER_FAILURE_CLASSES:
            raise ValueError("unsupported provider failure class")
        self.failure_class = failure_class
        super().__init__(self.MESSAGE)


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


class _ProviderCallError(RuntimeError):
    """Typed provider failure that never retains response or exception bodies."""

    def __init__(self, failure_class: str, *, status: Optional[int] = None) -> None:
        self.failure_class = failure_class
        self.status = status
        super().__init__(failure_class)


def _public_provider_failure_class(reason: str) -> str:
    """Map a private body-free reason to the fixed public P6 taxonomy."""

    if reason == "provider_http_auth_error":
        return "provider_credentials_unavailable"
    if reason in {
        "provider_http_rate_limited",
        "provider_http_server_error",
    } or reason.startswith("provider_transport_"):
        return "provider_transport_exhausted"
    if reason == "provider_protocol_usage_unverifiable":
        return "provider_usage_unverifiable"
    if reason in {
        "provider_protocol_model_mismatch",
        "provider_protocol_model_drift",
    }:
        return "provider_identity_mismatch"
    if reason.startswith("provider_protocol_") or reason in {
        "provider_http_client_error",
        "provider_http_unexpected_status",
    }:
        return "provider_protocol_incompatible"
    return "provider_transport_exhausted"


class _DuplicateProviderJsonKeyError(ValueError):
    """Internal marker for ambiguous provider-controlled JSON objects."""


class _NonFiniteProviderJsonNumberError(ValueError):
    """Internal marker for non-standard provider-controlled JSON numbers."""


def _reject_duplicate_provider_json_keys(
    pairs: Sequence[tuple[str, Any]],
) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateProviderJsonKeyError("duplicate provider JSON key")
        value[key] = item
    return value


def _reject_nonfinite_provider_json_number(value: str) -> Any:
    del value
    raise _NonFiniteProviderJsonNumberError("non-finite provider JSON number")


_ENDPOINT_CAPACITY_CONDITION = threading.Condition()
_ENDPOINT_CAPACITY_STATES: Dict[str, _EndpointCapacityState] = {}
_GLOBAL_CAPACITY_STATE = _GlobalCapacityState()


class LLMClient:
    """
    OpenAI-compatible LLM client with model fallback support.
    """

    MODEL_CONTEXT_KEEP_RECENT_TOOL_ROUNDS = 1
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
    TRANSIENT_CLIENT_RESPONSE_RETRY_LIMIT = 1
    TRANSIENT_CLIENT_RESPONSE_RETRY_DELAY_SECONDS = 1.0
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
        require_exact_response_model: bool = False,
        token_usage_ledger: Optional[ScanTokenUsageLedger] = None,
        llm_ref: str = "",
        response_model_map: Optional[Mapping[str, str]] = None,
    ):
        """
        Initialize LLM client.

        Args:
            api_key: API key
            base_url: API base URL or ordered list of API base URLs
            models: List of model names in order of priority
            response_model_map: Exact provider response identity for request aliases
            timeout: Request timeout in seconds
            max_retries: Retries per model
            retry_until_available: Compatibility flag. Transient failures remain
                bounded by the configured retry budget.
        """
        self.api_key = api_key
        self.base_urls = self._normalize_base_urls(base_url)
        self.base_url = self.base_urls[0]
        self.models = models
        self.response_model_map = {
            str(requested).strip(): str(response).strip()
            for requested, response in (response_model_map or {}).items()
            if str(requested).strip() and str(response).strip()
        }
        self.timeout = float(timeout) if timeout is not None else None
        self.max_retries = max_retries
        self.retry_until_available = bool(retry_until_available)
        self.max_tokens = max_tokens
        self.supports_structured_output = bool(supports_structured_output)
        self.require_exact_response_model = bool(require_exact_response_model)
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
        request_payload: Optional[Mapping[str, Any]] = None,
    ) -> int:
        """Return a conservative upper bound for one serialized request prompt.

        The historical character heuristic remains useful as a lower-bound
        sanity check, but it is not safe for formal admission.  The byte bound
        includes messages, tools and response format exactly as JSON plus a
        frozen allowance for provider chat-template framing.  Consequently an
        admitted request reserves enough room even for byte-fallback
        tokenization; the completion limit is reserved separately by the
        scan-wide ledger.
        """

        heuristic = cls.estimate_tokens(messages)
        serialized_payload: Dict[str, Any] = dict(request_payload or {})
        serialized_payload["messages"] = messages
        if tools:
            serialized_payload["tools"] = tools
        if response_format:
            serialized_payload["response_format"] = response_format
        rendered = json.dumps(
            serialized_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        template_item_count = max(1, len(messages)) + len(tools or [])
        conservative_bound = (
            len(rendered)
            + _REQUEST_PROMPT_TEMPLATE_BASE_ALLOWANCE
            + _REQUEST_PROMPT_TEMPLATE_PER_ITEM_ALLOWANCE * template_item_count
        )
        return max(1, heuristic, conservative_bound)

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
        request_payload: Optional[Mapping[str, Any]] = None,
        call_chain_id: str = "",
        attempt_index: int = 1,
    ) -> Optional[TokenUsageReservation]:
        manager = self.token_usage_ledger
        if manager is None:
            return None
        inherited_attribution = current_llm_usage_attribution()
        inherited_attribution.update(dict(usage_attribution or {}))
        attribution = LLMUsageAttribution.from_trace(
            trace_agent=trace_agent,
            trace_label=trace_label,
            llm_ref=self.llm_ref,
            explicit=inherited_attribution,
        )
        operation_kind = attribution.call_kind
        if operation_kind == "contract_regeneration":
            match = re.search(
                r"(?:^|[;\s])pass\s*=\s*([^;]+)",
                str(trace_label or ""),
                flags=re.IGNORECASE,
            )
            operation_kind = str(match.group(1)).strip() if match else ""
        logical_operation_id = ""
        if attribution.validation_cluster_uid and operation_kind:
            material = "\x00".join(
                (
                    attribution.agent,
                    attribution.validation_cluster_uid,
                    operation_kind,
                )
            )
            logical_operation_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return manager.reserve(
            self._estimate_request_prompt_tokens(
                messages,
                tools=tools,
                response_format=response_format,
                request_payload=request_payload,
            ),
            max_completion_tokens,
            attribution=attribution,
            model=model,
            call_chain_id=call_chain_id,
            attempt_index=attempt_index,
            logical_operation_id=logical_operation_id,
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
        provider_response_model: str = "",
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
            # Provider-controlled metadata is archived with the accounting
            # ledger.  Keep it on a fixed enum so an arbitrary response value
            # can never become an artifact/log side channel.
            finish_reason=(
                finish_reason
                if finish_reason
                in {
                    "stop",
                    "length",
                    "tool_calls",
                    "function_call",
                    "content_filter",
                    "error",
                }
                else "other"
            ),
            cached_prompt_tokens=self._usage_value(usage.get("cached_prompt_tokens")),
            reasoning_tokens=self._usage_value(usage.get("reasoning_tokens")),
            retry=retry,
            repair=repair,
            tool_call_count=tool_call_count,
            new_fact_count=new_fact_count,
            duration_ms=duration_ms,
            provider_response_model=provider_response_model,
        )
        return event.to_dict()

    @staticmethod
    def _provider_message_has_output(message: Mapping[str, Any]) -> bool:
        """Return whether a successful provider message contains model output.

        The predicate deliberately reduces the response to one boolean.  It is
        used only to reject an impossible all-zero strict usage record and
        never retains provider content in an exception, log, or ledger event.
        """

        content = message.get("content")
        reasoning = message.get("reasoning_content") or message.get("reasoning")
        return bool(
            (isinstance(content, str) and content)
            or (isinstance(reasoning, str) and reasoning)
            or message.get("tool_calls")
            or message.get("function_call")
        )

    def _normalized_provider_usage(
        self,
        value: Any,
        *,
        response_has_output: bool = False,
    ) -> Dict[str, Any]:
        """Normalize OpenAI-compatible usage variants without retaining content."""

        if not isinstance(value, Mapping):
            if self.require_exact_response_model:
                raise _ProviderCallError("provider_protocol_usage_unverifiable")
            return {}

        if self.require_exact_response_model:
            prompt = value.get("prompt_tokens")
            completion = value.get("completion_tokens")
            total = value.get("total_tokens")
            if any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in (prompt, completion, total)
            ):
                raise _ProviderCallError("provider_protocol_usage_unverifiable")
            assert isinstance(prompt, int)
            assert isinstance(completion, int)
            assert isinstance(total, int)
            if total != prompt + completion:
                raise _ProviderCallError("provider_protocol_usage_unverifiable")
            if response_has_output and prompt == completion == total == 0:
                raise _ProviderCallError("provider_protocol_usage_unverifiable")

            def optional_count(item: Any) -> int:
                return (
                    int(item)
                    if isinstance(item, int) and not isinstance(item, bool) and item >= 0
                    else 0
                )

            prompt_details = value.get("prompt_tokens_details")
            completion_details = value.get("completion_tokens_details")
            return {
                "prompt_tokens": prompt,
                "completion_tokens": completion,
                "total_tokens": total,
                "cached_prompt_tokens": optional_count(
                    value.get("cached_prompt_tokens")
                    if value.get("cached_prompt_tokens") is not None
                    else (
                        prompt_details.get("cached_tokens")
                        if isinstance(prompt_details, Mapping)
                        else None
                    )
                ),
                "reasoning_tokens": optional_count(
                    value.get("reasoning_tokens")
                    if value.get("reasoning_tokens") is not None
                    else (
                        completion_details.get("reasoning_tokens")
                        if isinstance(completion_details, Mapping)
                        else None
                    )
                ),
                "estimated": False,
            }

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
        _error: BaseException,
        cooldown_seconds: float,
    ) -> None:
        logger.warning(
            "Local file descriptor exhaustion while calling LLM; closing current "
            "thread HTTP session and cooling all base_urls for %.1fs",
            cooldown_seconds,
        )
        self.close_thread_session()
        self._mark_all_base_urls_cooldown(cooldown_seconds)

    @staticmethod
    def _http_failure_class(status: int) -> str:
        if status in {401, 403}:
            return "provider_http_auth_error"
        if status == 429:
            return "provider_http_rate_limited"
        if 500 <= status <= 599:
            return "provider_http_server_error"
        if 400 <= status <= 499:
            return "provider_http_client_error"
        return "provider_http_unexpected_status"

    @classmethod
    def _provider_failure_class(cls, error: BaseException) -> str:
        if isinstance(error, _ProviderCallError):
            return error.failure_class
        if cls._is_too_many_open_files(error):
            return "provider_transport_local_resource_exhausted"
        overload = cls._endpoint_overload_reason(error)
        if overload == "timeout":
            return "provider_transport_timeout"
        if overload == "ssl_error":
            return "provider_transport_tls_error"
        if overload == "connection_error":
            return "provider_transport_connection_error"
        if isinstance(error, (json.JSONDecodeError, UnicodeError, ValueError, TypeError)):
            return "provider_protocol_error"
        return "provider_transport_error"

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
            trace_session = recorder.begin_session(trace_agent or "direct_chat", trace_label)
            created_trace_session = True

        for model in self.models:
            logger.info(f"Using model: {model}")
            call_chain_id = (
                self.token_usage_ledger.new_call_chain_id()
                if self.token_usage_ledger is not None
                else ""
            )

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens or self.max_tokens,
            }

            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = tool_choice if tool_choice is not None else "auto"
                # The sealed P6 provider contract is an OpenAI-compatible
                # tools endpoint.  Keep each response as one deterministic
                # action/finalization boundary so a provider cannot batch a
                # validator final call with another action.  Non-strict
                # compatibility profiles do not receive this optional field.
                if self.require_exact_response_model:
                    payload["parallel_tool_calls"] = False
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
            transient_auth_retries_remaining = self.TRANSIENT_AUTH_RETRY_LIMIT
            transient_client_response_retries_remaining = self.TRANSIENT_CLIENT_RESPONSE_RETRY_LIMIT
            while attempt < total_attempts:
                retry_transient = False
                attempt += 1
                token = current_cancellation_token()
                if token is not None:
                    token.raise_if_cancelled()
                endpoint = self._select_base_url()
                post_attempt_delay = 0.0
                response: Optional[requests.Response] = None
                usage_reservation: Optional[TokenUsageReservation] = None
                usage_settled = False
                usage_rejected_before_model = False
                request_started: Optional[float] = None
                usage_failure_class = "provider_request_failed"
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
                        request_payload=payload,
                        call_chain_id=call_chain_id,
                        attempt_index=attempt,
                    )
                    attempt_payload = dict(payload)
                    if usage_reservation is not None:
                        attempt_payload["max_tokens"] = usage_reservation.completion_token_limit

                    if self._transport == "curl":
                        request_started = time.monotonic()
                        (
                            assembled_message,
                            finish_reason,
                            provider_usage,
                            provider_response_model,
                        ) = self._curl_chat_completion(
                            url,
                            attempt_payload,
                        )
                        self._validate_provider_response_model(
                            requested_model=model,
                            response_model=provider_response_model,
                        )
                        self._validate_provider_finish_reason(finish_reason)
                        prompt_tokens = LLMClient.estimate_tokens(messages)
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        usage: Dict[str, Any] = {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                            "estimated": True,
                        }
                        normalized_provider_usage = self._normalized_provider_usage(
                            provider_usage,
                            response_has_output=self._provider_message_has_output(
                                assembled_message
                            ),
                        )
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
                            provider_response_model=provider_response_model,
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
                        if recorder and trace_session:
                            recorder.record_exchange(
                                trace_session,
                                trace_iteration,
                                messages,
                                assembled_message,
                                finish_reason,
                                model,
                                prompt_tokens,
                                completion_tokens,
                            )
                            if created_trace_session:
                                recorder.record_session_end(
                                    trace_session,
                                    trace_iteration or 1,
                                    prompt_tokens + completion_tokens,
                                )
                        self._record_endpoint_success(endpoint)
                        return {
                            "choices": [
                                {
                                    "message": assembled_message,
                                    "finish_reason": finish_reason,
                                }
                            ],
                            "model": provider_response_model,
                            "requested_model": model,
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
                        json=attempt_payload,
                        timeout=request_timeout,
                        stream=True,
                        allow_redirects=False,
                    )

                    if response.status_code == 200:
                        (
                            assembled_message,
                            finish_reason,
                            provider_usage,
                            provider_response_model,
                        ) = self._assemble_chat_response_with_usage(response)
                        self._validate_provider_response_model(
                            requested_model=model,
                            response_model=provider_response_model,
                        )
                        self._validate_provider_finish_reason(finish_reason)

                        # Estimate single API call cost and log prominently
                        prompt_tokens = LLMClient.estimate_tokens(messages)
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        usage = {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                            "estimated": True,
                        }
                        normalized_provider_usage = self._normalized_provider_usage(
                            provider_usage,
                            response_has_output=self._provider_message_has_output(
                                assembled_message
                            ),
                        )
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
                            provider_response_model=provider_response_model,
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
                        if recorder and trace_session:
                            recorder.record_exchange(
                                trace_session,
                                trace_iteration,
                                messages,
                                assembled_message,
                                finish_reason,
                                model,
                                prompt_tokens,
                                completion_tokens,
                            )
                            if created_trace_session:
                                recorder.record_session_end(
                                    trace_session,
                                    trace_iteration or 1,
                                    prompt_tokens + completion_tokens,
                                )

                        self._record_endpoint_success(endpoint)
                        return {
                            "choices": [
                                {"message": assembled_message, "finish_reason": finish_reason}
                            ],
                            "model": provider_response_model,
                            "requested_model": model,
                            "usage": usage,
                        }

                    failure_class = self._http_failure_class(response.status_code)
                    transient_http_error = (
                        response.status_code >= 500 or response.status_code == 429
                    )
                    logger.warning(
                        "Model %s via %s failed (class=%s, status=%d, attempt=%d/%s)",
                        model,
                        endpoint.url,
                        failure_class,
                        response.status_code,
                        attempt,
                        (str(total_attempts)),
                    )

                    if transient_http_error:
                        retry_transient = True
                        if response.status_code == 429:
                            usage_rejected_before_model = True
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
                        logger.warning(
                            "Rate limited or server error on %s; cooling it down for %.1fs...",
                            endpoint.url,
                            wait_time,
                        )
                        usage_failure_class = failure_class
                        last_error = failure_class
                        continue
                    elif (
                        response.status_code == 401
                        and transient_auth_retries_remaining > 0
                        and attempt < total_attempts
                        and self._has_successful_call()
                    ):
                        # A provider can occasionally return an isolated 401 while
                        # concurrent requests using the same credential continue to
                        # succeed. Retry that condition once, but never turn a bad
                        # credential into an unbounded retry loop.
                        transient_auth_retries_remaining -= 1
                        usage_rejected_before_model = True
                        wait_time = self.TRANSIENT_AUTH_RETRY_DELAY_SECONDS
                        self._mark_base_url_cooldown(endpoint, wait_time)
                        post_attempt_delay = wait_time
                        usage_failure_class = failure_class
                        last_error = failure_class
                        logger.warning(
                            "Endpoint %s returned an isolated HTTP 401 after prior "
                            "successful authentication; retrying once after %.1fs",
                            endpoint.url,
                            wait_time,
                        )
                        continue
                    elif (
                        response.status_code == 400
                        and transient_client_response_retries_remaining > 0
                        and attempt < total_attempts
                    ):
                        # A busy OpenAI-compatible gateway can occasionally
                        # return an isolated 400 for a byte-identical request
                        # while concurrent requests on the same deployment are
                        # still establishing their first successes. Retry that
                        # exact request once even during the startup window.
                        # A deterministic schema/request rejection therefore
                        # fails on the second identical response and never
                        # degrades into an unbounded or mutated retry.
                        transient_client_response_retries_remaining -= 1
                        usage_rejected_before_model = True
                        post_attempt_delay = self.TRANSIENT_CLIENT_RESPONSE_RETRY_DELAY_SECONDS
                        usage_failure_class = failure_class
                        last_error = failure_class
                        logger.warning(
                            "Endpoint %s returned HTTP 400; retrying the "
                            "byte-identical request once",
                            endpoint.url,
                        )
                        continue
                    else:
                        usage_failure_class = failure_class
                        last_error = failure_class
                        break  # Try next model

                except P6BalancedTokenAdmissionError:
                    # Admission is a deterministic pre-provider decision.  It
                    # is never a transport failure and must not be retried or
                    # conservatively charged as a physical model call.
                    raise
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
                    if overload_reason is not None:
                        self._record_endpoint_overload(
                            endpoint,
                            reason=overload_reason,
                        )
                        self._mark_base_url_cooldown(endpoint, wait_time)
                    if local_fd_exhausted:
                        wait_time = max(wait_time, self.LOCAL_FD_EXHAUSTION_COOLDOWN_SECONDS)
                        self._recover_from_local_fd_exhaustion(e, wait_time)
                    is_last = attempt >= total_attempts
                    post_attempt_delay = 0.0 if is_last else wait_time
                    failure_class = self._provider_failure_class(e)
                    usage_failure_class = failure_class
                    if self.require_exact_response_model and failure_class.startswith(
                        "provider_protocol_"
                    ):
                        logger.warning(
                            "Strict provider response rejected (class=%s)",
                            failure_class,
                        )
                        post_attempt_delay = 0.0
                        last_error = failure_class
                        break
                    logger.warning(
                        "Model %s via %s request failed " "(class=%s, attempt=%d/%s, final=%s)",
                        model,
                        endpoint.url,
                        failure_class,
                        attempt,
                        (str(total_attempts)),
                        is_last,
                    )
                    last_error = failure_class
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
                            if usage_rejected_before_model:
                                manager.reject_before_model(
                                    usage_reservation,
                                    reason=usage_failure_class,
                                )
                            else:
                                manager.forfeit(
                                    usage_reservation,
                                    reason=usage_failure_class,
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

            logger.info(f"Falling back from model {model}...")

        raise ProviderFailureError(
            _public_provider_failure_class(last_error or "provider_request_failed")
        )

    def _curl_chat_completion(
        self,
        url: str,
        payload: Dict[str, Any],
    ) -> tuple[Dict[str, Any], str, Dict[str, Any], str]:
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
        if status_marker not in stdout:
            raise _ProviderCallError("provider_transport_missing_http_status")
        body, raw_status = stdout.rsplit(status_marker, 1)
        try:
            status = int(raw_status.strip()[-3:])
        except ValueError as exc:
            raise _ProviderCallError("provider_transport_invalid_http_status") from exc
        if proc.returncode != 0:
            raise _ProviderCallError("provider_transport_error", status=status)
        if status != 200:
            raise _ProviderCallError(self._http_failure_class(status), status=status)
        try:
            data = json.loads(
                body,
                object_pairs_hook=_reject_duplicate_provider_json_keys,
                parse_constant=(
                    _reject_nonfinite_provider_json_number
                    if self.require_exact_response_model
                    else None
                ),
            )
        except (
            json.JSONDecodeError,
            _DuplicateProviderJsonKeyError,
            _NonFiniteProviderJsonNumberError,
        ) as exc:
            raise _ProviderCallError("provider_protocol_non_json") from exc
        if not isinstance(data, dict):
            raise _ProviderCallError("provider_protocol_invalid_response")
        choices = data.get("choices") or []
        if not choices:
            raise _ProviderCallError("provider_protocol_missing_choices")
        if self.require_exact_response_model and (
            not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict)
        ):
            raise _ProviderCallError("provider_protocol_invalid_response")
        choice = choices[0] if isinstance(choices[0], dict) else {}
        raw_message = choice.get("message")
        if self.require_exact_response_model and not isinstance(raw_message, dict):
            raise _ProviderCallError("provider_protocol_invalid_response")
        message = raw_message or {}
        if not isinstance(message, dict):
            message = {"role": "assistant", "content": str(message)}
        response_tool_protocol = (
            "function_call"
            if message.get("function_call") is not None
            else ("tool_calls" if message.get("tool_calls") is not None else "")
        )
        if self.require_exact_response_model:
            self._validate_strict_provider_message(message, streaming=False)
        message = self._canonicalize_legacy_function_call(
            message,
            streaming=False,
        )
        if self.require_exact_response_model:
            # Validate the canonical shape as well.  The first validation above
            # accepts the legacy ``function_call`` envelope; after conversion,
            # the response must satisfy the same complete modern tool-call
            # contract as a native ``tool_calls`` response.
            self._validate_strict_provider_message(message, streaming=False)
        message.setdefault("role", "assistant")
        message.setdefault("content", "")
        raw_finish_reason = choice.get("finish_reason")
        if self.require_exact_response_model and (
            not isinstance(raw_finish_reason, str) or not raw_finish_reason
        ):
            raise _ProviderCallError("provider_protocol_invalid_response")
        finish_reason = str(raw_finish_reason or "stop")
        if self.require_exact_response_model:
            self._validate_strict_tool_finish_reason(
                finish_reason,
                tool_protocol=response_tool_protocol,
            )
        raw_usage = data.get("usage")
        usage: Dict[str, Any] = dict(raw_usage) if isinstance(raw_usage, dict) else {}
        raw_provider_response_model = data.get("model")
        provider_response_model = (
            raw_provider_response_model if isinstance(raw_provider_response_model, str) else ""
        )
        return message, finish_reason, usage, provider_response_model

    def _validate_provider_response_model(
        self, *, requested_model: str, response_model: str
    ) -> None:
        expected_response_model = self.response_model_map.get(requested_model, requested_model)
        # Some gateways preserve the exact requested deployment alias while
        # others return its exact versioned deployment identity. Both values
        # are source-controlled by the request -> response map; every unrelated
        # response identity still fails closed.
        allowed_response_models = {requested_model, expected_response_model}
        if self.require_exact_response_model and response_model not in allowed_response_models:
            raise _ProviderCallError("provider_protocol_model_mismatch")

    def _validate_provider_finish_reason(self, finish_reason: str) -> None:
        if self.require_exact_response_model and finish_reason not in {
            "stop",
            "tool_calls",
            "function_call",
        }:
            raise _ProviderCallError("provider_protocol_invalid_response")

    @staticmethod
    def _validate_strict_tool_finish_reason(
        finish_reason: str,
        *,
        tool_protocol: str,
    ) -> None:
        expected = {
            "": "stop",
            "tool_calls": "tool_calls",
            "function_call": "function_call",
        }.get(tool_protocol)
        if expected is None or finish_reason != expected:
            raise _ProviderCallError("provider_protocol_invalid_response")

    def _validate_strict_provider_message(
        self,
        message: Any,
        *,
        streaming: bool,
    ) -> None:
        """Reject ambiguous provider-controlled message shapes in P6 strict mode."""

        if not isinstance(message, Mapping):
            raise _ProviderCallError("provider_protocol_invalid_response")
        role = message.get("role")
        if role is not None and role != "assistant":
            raise _ProviderCallError("provider_protocol_invalid_response")
        if not streaming and role != "assistant":
            raise _ProviderCallError("provider_protocol_invalid_response")
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise _ProviderCallError("provider_protocol_invalid_response")
        has_tool_calls = message.get("tool_calls") is not None
        has_legacy_function_call = message.get("function_call") is not None
        if has_tool_calls and has_legacy_function_call:
            raise _ProviderCallError("provider_protocol_invalid_response")
        if has_legacy_function_call:
            self._validate_legacy_function_call(
                message.get("function_call"),
                streaming=streaming,
            )
        tool_calls = message.get("tool_calls")
        if not has_tool_calls:
            return
        if not isinstance(tool_calls, list):
            raise _ProviderCallError("provider_protocol_invalid_response")
        if len(tool_calls) > 1 or (not streaming and len(tool_calls) != 1):
            # ``parallel_tool_calls=false`` is part of the sealed request, but
            # it is only a provider hint.  Enforce the one-response/one-action
            # boundary locally before any caller can execute a sibling call.
            raise _ProviderCallError("provider_protocol_invalid_response")
        for tool_call in tool_calls:
            if not isinstance(tool_call, Mapping):
                raise _ProviderCallError("provider_protocol_invalid_response")
            allowed_tool_keys = {"id", "type", "function", "index"}
            if not set(tool_call) <= allowed_tool_keys:
                raise _ProviderCallError("provider_protocol_invalid_response")
            index = tool_call.get("index")
            if index is not None and (
                isinstance(index, bool) or not isinstance(index, int) or index < 0
            ):
                raise _ProviderCallError("provider_protocol_invalid_response")
            tool_id = tool_call.get("id")
            tool_type = tool_call.get("type")
            function = tool_call.get("function")
            if function is not None and not isinstance(function, Mapping):
                raise _ProviderCallError("provider_protocol_invalid_response")
            if isinstance(function, Mapping):
                if not set(function) <= {"name", "arguments"}:
                    raise _ProviderCallError("provider_protocol_invalid_response")
                for field in ("name", "arguments"):
                    item = function.get(field)
                    if item is not None and not isinstance(item, str):
                        raise _ProviderCallError("provider_protocol_invalid_response")
            if streaming:
                if tool_id is not None and (not isinstance(tool_id, str) or not tool_id):
                    raise _ProviderCallError("provider_protocol_invalid_response")
                if tool_type is not None and tool_type != "function":
                    raise _ProviderCallError("provider_protocol_invalid_response")
                if isinstance(function, Mapping):
                    name = function.get("name")
                    if name is not None and not name:
                        raise _ProviderCallError("provider_protocol_invalid_response")
                continue
            if not isinstance(tool_id, str) or not tool_id or tool_type != "function":
                raise _ProviderCallError("provider_protocol_invalid_response")
            if not isinstance(function, Mapping) or set(function) != {"name", "arguments"}:
                raise _ProviderCallError("provider_protocol_invalid_response")
            if not function.get("name"):
                raise _ProviderCallError("provider_protocol_invalid_response")
            try:
                self._parse_terminal_tool_args(function.get("arguments"))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise _ProviderCallError("provider_protocol_invalid_response") from exc

    @staticmethod
    def _validate_legacy_function_call(value: Any, *, streaming: bool) -> None:
        """Validate the deprecated OpenAI ``function_call`` response shape.

        Streaming deltas may split the name and arguments across chunks, but
        each fragment must still be an unambiguous string-only projection.
        A complete non-stream response must contain exactly both fields.
        """

        if not isinstance(value, Mapping):
            raise _ProviderCallError("provider_protocol_invalid_response")
        keys = set(value)
        allowed = {"name", "arguments"}
        if not keys or not keys <= allowed:
            raise _ProviderCallError("provider_protocol_invalid_response")
        if not streaming and keys != allowed:
            raise _ProviderCallError("provider_protocol_invalid_response")
        for field in keys:
            item = value.get(field)
            if not isinstance(item, str):
                raise _ProviderCallError("provider_protocol_invalid_response")
            if field == "name" and not streaming and not item:
                raise _ProviderCallError("provider_protocol_invalid_response")

    @classmethod
    def _canonicalize_legacy_function_call(
        cls,
        message: Mapping[str, Any],
        *,
        streaming: bool,
    ) -> Dict[str, Any]:
        """Return one modern canonical tool call for a legacy response.

        The synthetic id is content-bound and carries no provider-controlled
        body.  Mixed modern/legacy responses are always ambiguous and fail
        closed, including for non-strict compatibility clients.
        """

        canonical = dict(message)
        if "function_call" not in canonical:
            return canonical
        if canonical.get("function_call") is None:
            canonical.pop("function_call", None)
            return canonical
        if canonical.get("tool_calls") is not None:
            raise _ProviderCallError("provider_protocol_invalid_response")
        function_call = canonical.get("function_call")
        cls._validate_legacy_function_call(function_call, streaming=streaming)
        assert isinstance(function_call, Mapping)
        name = str(function_call.get("name") or "")
        arguments = str(function_call.get("arguments") or "")
        if not streaming and not name:
            raise _ProviderCallError("provider_protocol_invalid_response")
        identity = hashlib.sha256((name + "\x00" + arguments).encode("utf-8")).hexdigest()[:24]
        canonical.pop("function_call", None)
        canonical["tool_calls"] = [
            {
                "id": f"call_legacy_{identity}",
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            }
        ]
        return canonical

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
        message, finish_reason, _usage, _model = self._assemble_chat_response_with_usage(response)
        return message, finish_reason

    def _assemble_chat_response_with_usage(
        self,
        response: requests.Response,
    ) -> tuple[Dict[str, Any], str, Dict[str, Any], str]:
        """Assemble a response and retain only provider token-accounting fields."""

        content_pieces: List[str] = []
        reasoning_pieces: List[str] = []
        tool_calls_map: Dict[Any, Dict[str, Any]] = {}
        legacy_function_call: Dict[str, str] = {}
        tool_protocol = ""
        finish_reason = "stop"
        finish_reason_seen = False
        provider_usage: Dict[str, Any] = {}
        provider_response_model = ""
        provider_usage_seen = False

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
            raw_chunk_model = chunk.get("model")
            if self.require_exact_response_model and (
                not isinstance(raw_chunk_model, str) or not raw_chunk_model
            ):
                raise _ProviderCallError("provider_protocol_invalid_response")
            chunk_model = raw_chunk_model if isinstance(raw_chunk_model, str) else ""
            if chunk_model:
                if provider_response_model and chunk_model != provider_response_model:
                    raise _ProviderCallError("provider_protocol_model_drift")
                provider_response_model = chunk_model
            chunk_usage = chunk.get("usage")
            if (
                self.require_exact_response_model
                and "usage" in chunk
                and chunk_usage is not None
                and not isinstance(chunk_usage, dict)
            ):
                raise _ProviderCallError("provider_protocol_usage_unverifiable")
            if isinstance(chunk_usage, dict) and chunk_usage:
                usage_identity = {
                    key: chunk_usage.get(key)
                    for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                }
                recorded_usage_identity = {
                    key: provider_usage.get(key)
                    for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                }
                if (
                    self.require_exact_response_model
                    and provider_usage_seen
                    and usage_identity != recorded_usage_identity
                ):
                    raise _ProviderCallError("provider_protocol_usage_unverifiable")
                provider_usage_seen = True
                provider_usage.update(chunk_usage)
            choices = chunk.get("choices", [])
            if not choices:
                continue
            if self.require_exact_response_model and (
                not isinstance(choices, list)
                or len(choices) != 1
                or not isinstance(choices[0], dict)
            ):
                raise _ProviderCallError("provider_protocol_invalid_response")

            choice = choices[0]
            raw_delta = choice.get("delta")
            raw_message = choice.get("message")
            if self.require_exact_response_model and (
                ("delta" in choice and not isinstance(raw_delta, dict))
                or ("message" in choice and not isinstance(raw_message, dict))
            ):
                raise _ProviderCallError("provider_protocol_invalid_response")
            message_delta = raw_delta
            if not isinstance(message_delta, dict) or not message_delta:
                message_delta = raw_message or {}
            if self.require_exact_response_model and not isinstance(message_delta, dict):
                raise _ProviderCallError("provider_protocol_invalid_response")
            if not isinstance(message_delta, dict):
                message_delta = {}
            if self.require_exact_response_model:
                self._validate_strict_provider_message(message_delta, streaming=True)

            content = message_delta.get("content")
            if content:
                content_pieces.append(str(content))

            reasoning = message_delta.get("reasoning_content") or message_delta.get("reasoning")
            if reasoning:
                reasoning_pieces.append(str(reasoning))

            if message_delta.get("function_call") is not None:
                if tool_protocol == "tool_calls":
                    raise _ProviderCallError("provider_protocol_invalid_response")
                tool_protocol = "function_call"
                legacy_delta = message_delta.get("function_call")
                self._validate_legacy_function_call(legacy_delta, streaming=True)
                assert isinstance(legacy_delta, Mapping)
                for field in ("name", "arguments"):
                    piece = legacy_delta.get(field)
                    if isinstance(piece, str):
                        legacy_function_call[field] = legacy_function_call.get(field, "") + piece

            tool_calls = message_delta.get("tool_calls") or []
            if message_delta.get("tool_calls") is not None:
                if tool_protocol == "function_call":
                    raise _ProviderCallError("provider_protocol_invalid_response")
                tool_protocol = "tool_calls"
            if isinstance(tool_calls, list):
                for fallback_index, tool_call in enumerate(tool_calls):
                    if isinstance(tool_call, dict):
                        self._merge_tool_call(
                            tool_calls_map,
                            tool_call,
                            fallback_index,
                            strict=self.require_exact_response_model,
                        )

            if choice.get("finish_reason") is not None:
                if self.require_exact_response_model and finish_reason_seen:
                    raise _ProviderCallError("provider_protocol_invalid_response")
                finish_reason = choice["finish_reason"]
                finish_reason_seen = True

        if self.require_exact_response_model:
            if not finish_reason_seen or finish_reason not in {
                "stop",
                "tool_calls",
                "function_call",
            }:
                raise _ProviderCallError("provider_protocol_invalid_response")
            if tool_protocol == "tool_calls" and not tool_calls_map:
                raise _ProviderCallError("provider_protocol_invalid_response")
            if tool_protocol == "function_call" and not legacy_function_call:
                raise _ProviderCallError("provider_protocol_invalid_response")
            self._validate_strict_tool_finish_reason(
                finish_reason,
                tool_protocol=tool_protocol,
            )

        assembled_message: Dict[str, Any] = {"role": "assistant"}
        if content_pieces:
            assembled_message["content"] = "".join(content_pieces)
        if legacy_function_call:
            if (
                set(legacy_function_call) != {"name", "arguments"}
                or not legacy_function_call["name"]
            ):
                raise _ProviderCallError("provider_protocol_invalid_response")
            assembled_message["function_call"] = legacy_function_call
            assembled_message = self._canonicalize_legacy_function_call(
                assembled_message,
                streaming=False,
            )
            assembled_message.setdefault("content", "")
        elif tool_calls_map:
            assembled_message["tool_calls"] = [
                tool_calls_map[key] for key in sorted(tool_calls_map.keys(), key=str)
            ]
            assembled_message.setdefault("content", "")
        else:
            assembled_message.setdefault("content", "")
        if reasoning_pieces:
            assembled_message["reasoning_content"] = "".join(reasoning_pieces)

        if self.require_exact_response_model:
            # Streaming validation above intentionally permits partial deltas.
            # Revalidate the assembled response as one complete message so a
            # missing id/type/name/arguments fragment can never reach an agent
            # or be accounted as a successful provider action.
            self._validate_strict_provider_message(assembled_message, streaming=False)

        return assembled_message, finish_reason, provider_usage, provider_response_model

    def _iter_chat_chunks(
        self,
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
            if decoded_line.startswith(":"):
                continue
            is_data_line = decoded_line.startswith("data:")
            if self.require_exact_response_model and not is_data_line:
                raise _ProviderCallError("provider_protocol_invalid_response")
            if is_data_line:
                decoded_line = decoded_line[len("data:") :].strip()
            if decoded_line == "[DONE]":
                break
            if not decoded_line.startswith("{"):
                if self.require_exact_response_model:
                    raise _ProviderCallError("provider_protocol_invalid_response")
                continue
            try:
                chunk = json.loads(
                    decoded_line,
                    object_pairs_hook=_reject_duplicate_provider_json_keys,
                    parse_constant=(
                        _reject_nonfinite_provider_json_number
                        if self.require_exact_response_model
                        else None
                    ),
                )
            except (
                _DuplicateProviderJsonKeyError,
                _NonFiniteProviderJsonNumberError,
            ) as exc:
                raise _ProviderCallError("provider_protocol_invalid_response") from exc
            except json.JSONDecodeError as exc:
                if self.require_exact_response_model:
                    raise _ProviderCallError("provider_protocol_invalid_response") from exc
                logger.debug("Ignoring malformed chat completion line")
                continue
            if isinstance(chunk, dict):
                last_valid_chunk_at = time.monotonic()
                yield chunk
            elif self.require_exact_response_model:
                raise _ProviderCallError("provider_protocol_invalid_response")

    @staticmethod
    def _merge_tool_call(
        tool_calls_map: Dict[Any, Dict[str, Any]],
        tool_call: Dict[str, Any],
        fallback_index: int,
        *,
        strict: bool = False,
    ) -> None:
        idx = tool_call.get("index", fallback_index)
        if strict and tool_calls_map and idx not in tool_calls_map:
            raise _ProviderCallError("provider_protocol_invalid_response")
        existing = tool_calls_map.setdefault(idx, {})

        for key in ("id", "type", "index"):
            if tool_call.get(key) is not None:
                if strict and key in existing and existing[key] != tool_call[key]:
                    raise _ProviderCallError("provider_protocol_invalid_response")
                existing[key] = tool_call[key]

        function_delta = tool_call.get("function")
        if isinstance(function_delta, dict):
            function = existing.setdefault("function", {})
            if function_delta.get("name"):
                if (
                    strict
                    and function.get("name") is not None
                    and function["name"] != function_delta["name"]
                ):
                    raise _ProviderCallError("provider_protocol_invalid_response")
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
    ) -> List[Dict[str, Any]]:
        """
        Build the model-facing context without mutating the full transcript.

        Tool results are the main source of context growth in long agent loops.
        Keep the most recent tool round verbatim so the model can finish the
        active reasoning step, and compact older large tool results into
        structured summaries that preserve lookup provenance and key facts.
        """
        keep_tool_ids = self._recent_tool_result_ids_to_keep(conversation)
        projected: List[Dict[str, Any]] = []
        compacted_count = 0
        original_chars = 0
        compacted_chars = 0

        for message in conversation:
            role = message.get("role")
            projected_message = self._copy_message_for_model(message)
            if role == "assistant" and not preserve_reasoning_metadata:
                # reasoning_content is provider-specific scratchpad text. It is
                # useful for local diagnostics but very expensive to replay.
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
        replay_identical_tool_result: bool = True,
        terminal_tool_name: Optional[str] = None,
        terminal_tool_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        terminal_tool_validator: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        terminal_tool_required: bool = False,
        max_identical_invalid_terminal_calls: int = 3,
        max_invalid_terminal_calls: int = 5,
        preserve_reasoning_metadata: bool = False,
    ) -> Dict[str, Any]:
        """
        Run a conversation loop with tool calling support.
        """
        conversation = messages.copy()
        iterations = 0
        tool_call_history: Dict[str, List[Dict[str, Any]]] = {}
        loop_guard_recovery: Optional[Dict[str, Any]] = None
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
        if terminal_tool_handler is None and terminal_tool_validator is not None:
            terminal_tool_handler = terminal_tool_validator
        recorder = get_conversation_recorder()
        trace_session = (
            recorder.begin_session(trace_agent or "unknown_agent", trace_label)
            if recorder
            else None
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
            force_no_tool_final = loop_guard_recovery is not None or executor_requested_final
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
            elif force_no_tool_final:
                pass
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

            model_conversation = self._prepare_messages_for_model(
                conversation,
                preserve_reasoning_metadata=preserve_reasoning_metadata,
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
            request_tools = None if final_iteration else tools_schema
            if final_iteration and terminal_tool_name:
                terminal_schemas = [
                    schema
                    for schema in tools_schema
                    if isinstance(schema, dict)
                    and isinstance(schema.get("function"), dict)
                    and schema["function"].get("name") == terminal_tool_name
                ]
                request_tools = terminal_schemas or None
            response = self.chat_completion(
                model_conversation,
                tools=request_tools,
                trace_agent=trace_agent,
                trace_label=trace_label,
                trace_iteration=iterations,
                trace_session=trace_session,
            )

            # Extract assistant message
            choice = response.get("choices", [{}])[0]
            message = choice.get("message", {})
            finish_reason = choice.get("finish_reason")
            provider_model = response.get("model") or (self.models[0] if self.models else None)
            if self.require_exact_response_model:
                try:
                    self._validate_strict_provider_message(message, streaming=False)
                except _ProviderCallError as exc:
                    raise ProviderFailureError(
                        _public_provider_failure_class(exc.failure_class)
                    ) from exc
                # The P6 provider contract accepts only native, structured
                # ``tool_calls``.  XML invoke tags are a legacy compatibility
                # syntax: converting them into synthetic calls here would
                # bypass the strict response validator (including its
                # single-action batch rule) and could execute provider prose.
                if not message.get("tool_calls") and "<invoke name=" in str(
                    message.get("content") or ""
                ):
                    raise ProviderFailureError("provider_protocol_incompatible")
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
                if recorder and trace_session:
                    recorder.record_session_end(trace_session, iterations, final_tokens)
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
                final_tokens = self.estimate_tokens(
                    self._prepare_messages_for_model(
                        conversation,
                        preserve_reasoning_metadata=preserve_reasoning_metadata,
                    )
                )
                if recorder and trace_session:
                    recorder.record_session_end(
                        trace_session,
                        iterations,
                        final_tokens,
                        truncated=max_iteration_final,
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
            if (
                not self.require_exact_response_model
                and not final_iteration
                and not tool_calls
                and "<invoke name=" in content
            ):
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
                if recorder and trace_session:
                    recorder.record_session_end(trace_session, iterations, final_tokens)
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
            force_final_after_loop_guard = False
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
                    raw_terminal_args = terminal_function.get("arguments")
                    try:
                        terminal_args = self._parse_terminal_tool_args(raw_terminal_args)
                        terminal_function["arguments"] = json.dumps(
                            terminal_args, ensure_ascii=False
                        )
                    except (TypeError, ValueError, json.JSONDecodeError):
                        terminal_args = {}
                        terminal_function["arguments"] = json.dumps(terminal_args)
                        terminal_failure_class = "terminal_tool_arguments_invalid"
                    else:
                        terminal_failure_class = ""

                    validation: Dict[str, Any] = {"valid": True, "payload": terminal_args}
                    if terminal_failure_class:
                        validation = {
                            "valid": False,
                            "error": terminal_failure_class,
                        }
                    elif mixed_calls:
                        validation = {
                            "valid": False,
                            "error": "terminal_tool_mixed_calls",
                        }
                    elif duplicate_calls:
                        validation = {
                            "valid": False,
                            "error": "terminal_tool_duplicate_calls",
                        }
                    elif terminal_tool_handler:
                        try:
                            handled = terminal_tool_handler(terminal_args)
                            if isinstance(handled, dict):
                                validation = handled
                            else:
                                validation = {"valid": bool(handled), "payload": terminal_args}
                        except Exception:
                            validation = {
                                "valid": False,
                                "error": "terminal_tool_handler_failed",
                            }
                        if not validation.get("valid"):
                            validation = {
                                "valid": False,
                                "error": "terminal_tool_payload_invalid",
                            }

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
                            )
                        final_tokens = self.estimate_tokens(
                            self._prepare_messages_for_model(
                                conversation,
                                preserve_reasoning_metadata=preserve_reasoning_metadata,
                            )
                        )
                        if recorder and trace_session:
                            recorder.record_session_end(trace_session, iterations, final_tokens)
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
                        )
                    terminal_invalid_call_count += 1
                    failure_signature = self._terminal_failure_signature(
                        terminal_tool_name,
                        terminal_args,
                        raw_arguments=raw_terminal_args,
                        parse_failed=bool(terminal_failure_class),
                        error=validation_error,
                    )
                    arguments_identity = hashlib.sha256(
                        self._canonical_tool_argument_text(raw_terminal_args).encode("utf-8")
                    ).hexdigest()
                    failure_record = {
                        "iteration": iterations,
                        "arguments_sha256": arguments_identity,
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
                                "arguments_sha256": failure_record["arguments_sha256"],
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
                        if recorder and trace_session:
                            recorder.record_session_end(
                                trace_session,
                                iterations,
                                final_tokens,
                                truncated=False,
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
                # A response that mixes or duplicates the authorization tool
                # is rejected as one indivisible batch.  Do not execute a
                # sibling action after observing an invalid final decision.
                tool_calls = (
                    []
                    if mixed_calls or duplicate_calls
                    else [call for call in tool_calls if call not in terminal_calls]
                )

            for tool_call in tool_calls:
                tool_id = tool_call.get("id")
                function = tool_call.get("function", {})
                func_name = function.get("name")
                func_args_str = function.get("arguments", "{}")

                logger.info(f"Tool call: {func_name}")

                try:
                    func_args = self._parse_tool_args(func_args_str)

                    # VERY IMPORTANT: Re-serialize the corrected dict back into the conversation history
                    # so that strict upstreams like GLM-4/5 do not throw 400 Bad Request on "Expecting ','"
                    function["arguments"] = json.dumps(func_args, ensure_ascii=False)

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
                    if covered_snippet_call is not None:
                        repeated_call_count = 0
                        covering_result = covered_snippet_call.get("result")
                        result = dict(covering_result) if isinstance(covering_result, dict) else {}
                        result["cached_tool_result"] = True
                        result["covered_file_snippet_replay"] = True
                        result["repeat_call_warning"] = self._build_covered_file_snippet_notice(
                            func_args,
                            tool_id,
                            covered_snippet_call,
                        )
                        logger.warning(
                            "Replayed cached result for covered get_file_snippet range: "
                            "%s (covered by %s)",
                            func_args,
                            covered_snippet_call.get("arguments"),
                        )
                    elif (
                        max_identical_tool_calls > 0
                        and len(previous_calls) >= max_identical_tool_calls
                    ):
                        repeated_call_count = len(previous_calls) + 1
                        if (
                            replay_identical_tool_result
                            and cached_previous_result is not None
                            and not cached_replayed
                        ):
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
                        )

                    # A program-owned checker may close the security decision
                    # while handling one tool call in a model response that
                    # contains several calls.  Stop the current tool round at
                    # that exact boundary: calling the remaining tools would
                    # be post-proof work even though the model emitted their
                    # requests before the proof existed.  The existing hook
                    # below validates and returns the terminal payload without
                    # starting another model iteration.
                    programmatic_terminal = getattr(
                        tool_executor,
                        "_zscope_programmatic_terminal_payload",
                        None,
                    )
                    if callable(programmatic_terminal):
                        try:
                            terminal_after_tool = programmatic_terminal()
                        except Exception as exc:
                            logger.warning("Programmatic terminal hook failed: %s", exc)
                            terminal_after_tool = None
                        if isinstance(terminal_after_tool, dict):
                            break

                    if isinstance(result, dict) and result.get("repeat_call_guard"):
                        loop_guard_recovery = {
                            "tool": func_name,
                            "arguments": func_args,
                            "repeat_count": repeated_call_count,
                        }
                        logger.error(
                            "Conversation hit repeated identical tool call; forcing final "
                            "no-tool response: "
                            "%s %s (repeat #%d)",
                            func_name,
                            func_args,
                            repeated_call_count,
                        )
                        conversation.append(
                            {
                                "role": "user",
                                "content": (
                                    "The loop guard blocked a repeated identical tool call. "
                                    "The latest tool message contains the cached result or the "
                                    "available evidence for that request. Tool use is now disabled. "
                                    "Produce the required final answer from the evidence already in "
                                    "this conversation. If the expected output is JSON, output one "
                                    "valid JSON block now."
                                ),
                            }
                        )
                        force_final_after_loop_guard = True
                        break

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
                            {},
                            {},
                            error=str(e),
                        )
            if force_final_after_loop_guard:
                continue

            programmatic_terminal = getattr(
                tool_executor,
                "_zscope_programmatic_terminal_payload",
                None,
            )
            if callable(programmatic_terminal):
                try:
                    payload = programmatic_terminal()
                except Exception as exc:
                    logger.warning("Programmatic terminal hook failed: %s", exc)
                    payload = None
                if isinstance(payload, dict):
                    programmatic_validation: Dict[str, Any] = {
                        "valid": True,
                        "payload": payload,
                    }
                    if terminal_tool_handler:
                        try:
                            handled = terminal_tool_handler(payload)
                            programmatic_validation = (
                                handled
                                if isinstance(handled, dict)
                                else {"valid": bool(handled), "payload": payload}
                            )
                        except Exception as exc:
                            programmatic_validation = {"valid": False, "error": str(exc)}
                    if programmatic_validation.get("valid"):
                        terminal_payload = programmatic_validation.get("payload", payload)
                        final_tokens = self.estimate_tokens(
                            self._prepare_messages_for_model(
                                conversation,
                                preserve_reasoning_metadata=preserve_reasoning_metadata,
                            )
                        )
                        if recorder and trace_session:
                            recorder.record_session_end(trace_session, iterations, final_tokens)
                        return {
                            "content": "",
                            "conversation": conversation,
                            "terminal_tool_payload": terminal_payload,
                            "terminal_tool_name": terminal_tool_name,
                            "terminal_tool_valid": True,
                            "terminal_tool_call_count": terminal_tool_call_count,
                            "terminal_invalid_call_count": terminal_invalid_call_count,
                            "programmatic_terminal": True,
                            "iterations": iterations,
                            "context_tokens": final_tokens,
                            "api_call_count": iterations,
                            "cumulative_prompt_tokens": cumulative_prompt_tokens,
                            "cumulative_completion_tokens": cumulative_completion_tokens,
                            "cumulative_total_tokens": (
                                cumulative_prompt_tokens + cumulative_completion_tokens
                            ),
                            "tool_call_count": self._count_tool_result_messages(conversation),
                            "finish_reason": last_finish_reason,
                            "provider_model": last_provider_model,
                            "last_assistant_preview": self._assistant_preview(last_message),
                        }

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
        if recorder and trace_session:
            recorder.record_session_end(
                trace_session,
                iterations,
                final_tokens,
                truncated=iterations >= max_iterations,
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
    def _canonical_tool_argument_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError):
            return f"invalid:{type(value).__name__}"

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

    @staticmethod
    def _parse_terminal_tool_args(value: Any) -> Dict[str, Any]:
        """Parse final-tool arguments as one strict JSON object.

        Unlike ordinary exploratory tool calls, a terminal authorization is
        never repaired with ``literal_eval`` or heuristic extraction.  The
        failure is body-free and duplicate/non-finite JSON is rejected.
        """

        if isinstance(value, dict):
            try:
                json.dumps(value, allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise ValueError("terminal_tool_arguments_invalid") from exc
            return dict(value)
        if not isinstance(value, str) or not value:
            raise ValueError("terminal_tool_arguments_invalid")

        def reject_constant(_value: str) -> Any:
            raise ValueError("terminal_tool_arguments_invalid")

        try:
            parsed = json.loads(
                value,
                object_pairs_hook=_reject_duplicate_provider_json_keys,
                parse_constant=reject_constant,
            )
        except (json.JSONDecodeError, _DuplicateProviderJsonKeyError, ValueError) as exc:
            raise ValueError("terminal_tool_arguments_invalid") from exc
        if not isinstance(parsed, dict):
            raise ValueError("terminal_tool_arguments_invalid")
        return parsed

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
