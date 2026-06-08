"""
Enhanced LLM client with model fallback support.
"""

import ast
from collections import deque
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
import random
import re
import json
import logging
import threading
import time
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Union, cast

import requests

from ..common.utils import extract_json_blocks
from .conversation_recorder import ConversationSession, get_conversation_recorder

logger = logging.getLogger(__name__)


@dataclass
class _BaseUrlState:
    url: str
    requests_started: Deque[float] = field(default_factory=deque)
    cooldown_until: float = 0.0


@dataclass
class _EndpointCapacityState:
    url: str
    max_concurrent_requests: int = 0
    in_flight: int = 0


_ENDPOINT_CAPACITY_CONDITION = threading.Condition()
_ENDPOINT_CAPACITY_STATES: Dict[str, _EndpointCapacityState] = {}


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
        timeout: int = 120,
        max_retries: int = 2,
        max_tokens: int = 4096,
        base_url_rate_limit_per_minute: int = 0,
        base_url_max_concurrent_requests: int = 0,
    ):
        """
        Initialize LLM client.
        
        Args:
            api_key: API key
            base_url: API base URL or ordered list of API base URLs
            models: List of model names in order of priority
            timeout: Request timeout in seconds
            max_retries: Retries per model
        """
        self.api_key = api_key
        self.base_urls = self._normalize_base_urls(base_url)
        self.base_url = self.base_urls[0]
        self.models = models
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens
        self.base_url_rate_limit_per_minute = max(0, int(base_url_rate_limit_per_minute or 0))
        self.base_url_max_concurrent_requests = max(0, int(base_url_max_concurrent_requests or 0))
        self._base_url_states = [_BaseUrlState(url=url) for url in self.base_urls]
        self._endpoint_capacity_states = {
            url: self._shared_endpoint_capacity_state(
                url,
                self.base_url_max_concurrent_requests,
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
        self._thread_local = threading.local()
        self.session = self._new_session()
        self._thread_local.session = self.session

    @staticmethod
    def _shared_endpoint_capacity_state(
        url: str,
        max_concurrent_requests: int,
    ) -> _EndpointCapacityState:
        with _ENDPOINT_CAPACITY_CONDITION:
            state = _ENDPOINT_CAPACITY_STATES.get(url)
            if state is None:
                state = _EndpointCapacityState(url=url)
                _ENDPOINT_CAPACITY_STATES[url] = state
            if max_concurrent_requests > 0:
                state.max_concurrent_requests = max(
                    state.max_concurrent_requests,
                    max_concurrent_requests,
                )
            return state

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update(self._session_headers)
        return session

    def _session_for_thread(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = self._new_session()
            self._thread_local.session = session
        return cast(requests.Session, session)

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
            now = time.monotonic()
            with self._base_url_condition:
                for state in self._base_url_states:
                    self._prune_recent_requests(state, now)

                candidates = [
                    state
                    for state in self._base_url_states
                    if (
                        state.cooldown_until <= now
                        and self._has_minute_capacity(state)
                        and self._has_concurrent_capacity(self._endpoint_capacity_states[state.url])
                    )
                ]
                if candidates:
                    selected = min(
                        candidates,
                        key=lambda state: (
                            len(state.requests_started),
                            self._endpoint_capacity_states[state.url].in_flight,
                        ),
                    )
                    selected.requests_started.append(now)
                    self._endpoint_capacity_states[selected.url].in_flight += 1
                    return selected

                blocked_by_concurrency_only = any(
                    state.cooldown_until <= now
                    and self._has_minute_capacity(state)
                    and not self._has_concurrent_capacity(self._endpoint_capacity_states[state.url])
                    for state in self._base_url_states
                )
                wait_until = min(
                    self._next_available_at(state, now) for state in self._base_url_states
                )

                wait_time = max(0.05, min(wait_until - now, 10.0))
                self._log_base_url_wait(blocked_by_concurrency_only, wait_time, now)
                self._base_url_condition.wait(timeout=wait_time)

    def _release_base_url(self, state: _BaseUrlState) -> None:
        with self._base_url_condition:
            endpoint = self._endpoint_capacity_states.get(state.url)
            if endpoint is not None:
                endpoint.in_flight = max(0, endpoint.in_flight - 1)
            self._base_url_condition.notify_all()

    def _mark_base_url_cooldown(self, state: _BaseUrlState, seconds: float) -> None:
        if seconds <= 0:
            return
        until = time.monotonic() + seconds
        with self._base_url_condition:
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

    def _has_minute_capacity(self, state: _BaseUrlState) -> bool:
        if self.base_url_rate_limit_per_minute <= 0:
            return True
        return len(state.requests_started) < self.base_url_rate_limit_per_minute

    def _has_concurrent_capacity(self, state: _EndpointCapacityState) -> bool:
        if state.max_concurrent_requests <= 0:
            return True
        return state.in_flight < state.max_concurrent_requests

    def _next_available_at(self, state: _BaseUrlState, now: float) -> float:
        available_at = max(state.cooldown_until, now)
        if (
            self.base_url_rate_limit_per_minute > 0
            and len(state.requests_started) >= self.base_url_rate_limit_per_minute
        ):
            available_at = max(available_at, state.requests_started[0] + 60.0)
        if not self._has_concurrent_capacity(self._endpoint_capacity_states[state.url]):
            available_at = max(available_at, now + 0.5)
        return available_at

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

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        trace_agent: Optional[str] = None,
        trace_label: Optional[str] = None,
        trace_iteration: Optional[int] = None,
        trace_session: Optional[ConversationSession] = None,
    ) -> Dict[str, Any]:
        """
        Send chat completion request with model fallback.
        """
        last_error = None
        recorder = get_conversation_recorder()
        created_trace_session = False
        if recorder and trace_session is None:
            trace_session = recorder.begin_session(trace_agent or "direct_chat", trace_label)
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
                payload["tool_choice"] = "auto"
            
            # Force streaming to bypass middle-proxy timeouts (e.g. 504 on 120s limit)
            payload["stream"] = True

            total_attempts = (self.max_retries + 1) * max(1, len(self._base_url_states))
            for attempt in range(total_attempts):
                endpoint = self._select_base_url()
                post_attempt_delay = 0.0
                try:
                    url = self._chat_completion_url(endpoint.url)
                    
                    response = self._session_for_thread().post(
                        url, json=payload, timeout=self.timeout, stream=True
                    )

                    if response.status_code == 200:
                        assembled_message, finish_reason = self._assemble_chat_response(response)
                            
                        # Estimate single API call cost and log prominently
                        prompt_tokens = LLMClient.estimate_tokens(messages)
                        completion_tokens = LLMClient.estimate_tokens([assembled_message])
                        
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

                        return {
                            "choices": [{
                                "message": assembled_message,
                                "finish_reason": finish_reason
                            }],
                            "usage": {
                                "prompt_tokens": prompt_tokens,
                                "completion_tokens": completion_tokens,
                                "total_tokens": prompt_tokens + completion_tokens,
                                "estimated": True,
                            },
                        }
                    
                    error_msg = f"HTTP {response.status_code}: {response.text}"
                    logger.warning(
                        "Model %s via %s failed (attempt %d/%d): %s",
                        model,
                        endpoint.url,
                        attempt + 1,
                        total_attempts,
                        error_msg,
                    )
                    
                    if response.status_code >= 500 or response.status_code == 429:
                        retry_after = self._retry_after_seconds(response)
                        wait_time = retry_after or min(2**attempt, 10) + random.uniform(0, 3)
                        self._mark_base_url_cooldown(endpoint, wait_time)
                        logger.warning(
                            "Rate limited or server error on %s; cooling it down for %.1fs...",
                            endpoint.url,
                            wait_time,
                        )
                        last_error = error_msg
                        continue
                    else:
                        last_error = error_msg
                        break # Try next model
                        
                except Exception as e:
                    wait_time = min(2**attempt, 10) + random.uniform(0, 3)
                    is_last = attempt >= total_attempts - 1
                    post_attempt_delay = 0.0 if is_last else wait_time
                    if is_last:
                        logger.warning(
                            "Model %s via %s request error (attempt %d/%d, final): %s",
                            model,
                            endpoint.url,
                            attempt + 1,
                            total_attempts,
                            e,
                        )
                    else:
                        logger.warning(
                            "Model %s via %s request error "
                            "(attempt %d/%d, retrying after %.1fs): %s",
                            model,
                            endpoint.url,
                            attempt + 1,
                            total_attempts,
                            wait_time,
                            e,
                        )
                    last_error = str(e)
                    continue
                finally:
                    self._release_base_url(endpoint)
                    if post_attempt_delay > 0:
                        time.sleep(post_attempt_delay)
            
            logger.info(f"Falling back from model {model}...")
            
        raise Exception(f"All models failed. Last error: {last_error}")

    def _assemble_chat_response(self, response: requests.Response) -> tuple[Dict[str, Any], str]:
        """Assemble either SSE chunks or a plain JSON chat completion response."""
        content_pieces: List[str] = []
        reasoning_pieces: List[str] = []
        tool_calls_map: Dict[Any, Dict[str, Any]] = {}
        finish_reason = "stop"

        stream_deadline = max(float(self.timeout) * 3.0, 300.0)
        for chunk in self._iter_chat_chunks(
            response,
            max_stream_seconds=stream_deadline,
            max_idle_valid_chunk_seconds=float(self.timeout),
        ):
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

            reasoning = (
                message_delta.get("reasoning_content")
                or message_delta.get("reasoning")
            )
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

        return assembled_message, finish_reason

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
            now = time.monotonic()
            if (
                max_stream_seconds is not None
                and now - stream_started_at > max_stream_seconds
            ):
                raise TimeoutError(
                    f"Chat completion stream exceeded {max_stream_seconds:.0f}s"
                )

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
                decoded_line = decoded_line[len("data:"):].strip()
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
                function["arguments"] = (
                    str(function.get("arguments", ""))
                    + str(function_delta.get("arguments", ""))
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
            if role == "assistant":
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
                {
                    **tool_call,
                    "function": dict(tool_call.get("function") or {}),
                }
                if isinstance(tool_call, dict)
                else tool_call
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
            force_no_tool_final = loop_guard_recovery is not None
            final_iteration = max_iteration_final or force_no_tool_final
            if max_iteration_final:
                conversation.append(
                    {
                        "role": "user",
                        "content": (
                            f"This is the final allowed iteration ({iterations}/{max_iterations}). "
                            "Tool use is now disabled. Produce the best final answer from the current "
                            "conversation context. If the expected output is JSON, output valid JSON now. "
                            "Do not ask for more tools or more turns."
                        ),
                    }
                )
            elif force_no_tool_final:
                pass
            elif (
                not warned_low_iterations
                and remaining_after_this <= low_iteration_threshold
            ):
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

            model_conversation = self._prepare_messages_for_model(conversation)
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
            response = self.chat_completion(
                model_conversation,
                tools=None if final_iteration else tools_schema,
                trace_agent=trace_agent,
                trace_label=trace_label,
                trace_iteration=iterations,
                trace_session=trace_session,
            )

            # Extract assistant message
            choice = response.get("choices", [{}])[0]
            message = choice.get("message", {})
            finish_reason = choice.get("finish_reason")
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
                content = self._get_combined_content(conversation)
                final_tokens = self.estimate_tokens(
                    self._prepare_messages_for_model(conversation)
                )
                logger.info(f"Conversation complete: {iterations} iterations, final context ≈ {final_tokens:,} tokens")
                if recorder and trace_session:
                    recorder.record_session_end(trace_session, iterations, final_tokens)
                result_payload = {
                    "content": content,
                    "conversation": conversation,
                    "iterations": iterations,
                    "context_tokens": final_tokens,
                    "cumulative_prompt_tokens": cumulative_prompt_tokens,
                    "cumulative_completion_tokens": cumulative_completion_tokens,
                    "cumulative_total_tokens": cumulative_prompt_tokens + cumulative_completion_tokens,
                    "tool_call_count": self._count_tool_result_messages(conversation),
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
                logger.warning(f"Model {self.models[0] if self.models else 'unknown'} output truncated! Prompting to continue...")
                conversation.append({"role": "user", "content": "请继续"})
                continue

            # Handle tool calls
            tool_calls = message.get("tool_calls", [])
            if final_iteration and tool_calls:
                logger.warning(
                    "Ignoring %d tool calls returned after tool use was disabled.",
                    len(tool_calls),
                )
                message["tool_calls"] = []
                tool_calls = []
            
            # --- XML Fallback (For GLM/Minimax models that emit raw text invoke tags) ---
            content = message.get("content", "")
            if not final_iteration and not tool_calls and "<invoke name=" in content:
                import uuid
                invokes = re.finditer(r'<invoke name="([^"]+)">([\s\S]*?)(?:</invoke>|$)', content)
                for match in invokes:
                    xml_func_name = match.group(1)
                    xml_param_str = match.group(2)
                    xml_args = {}
                    for param_match in re.finditer(r'<parameter name="([^"]+)">([\s\S]*?)(?=(?:</parameter>|<parameter|</invoke>|$))', xml_param_str):
                        # Attempt to cast numeric strings to int if applicable, else keep string
                        xml_val: Any = param_match.group(2).strip()
                        xml_val = re.sub(r'</.*$', '', str(xml_val), flags=re.DOTALL).strip()
                        if str(xml_val).isdigit():
                            xml_val = int(xml_val)
                        xml_args[param_match.group(1)] = xml_val
                        
                    tool_calls.append({
                        "id": f"call_xml_{uuid.uuid4().hex[:10]}",
                        "type": "function",
                        "function": {
                            "name": xml_func_name,
                            "arguments": json.dumps(xml_args, ensure_ascii=False)
                        }
                    })
                # If we synthetically built tool calls, we should ensure the LLM knows it made them.
                if tool_calls and "tool_calls" not in message:
                    message["tool_calls"] = tool_calls
            # --------------------------------------------------------------------------

            if not tool_calls:
                content = self._get_combined_content(conversation)
                final_tokens = self.estimate_tokens(
                    self._prepare_messages_for_model(conversation)
                )
                logger.info(f"Conversation complete (no more tool calls): {iterations} iterations, final context ≈ {final_tokens:,} tokens")
                if recorder and trace_session:
                    recorder.record_session_end(trace_session, iterations, final_tokens)
                result_payload = {
                    "content": content,
                    "conversation": conversation,
                    "iterations": iterations,
                    "context_tokens": final_tokens,
                    "cumulative_prompt_tokens": cumulative_prompt_tokens,
                    "cumulative_completion_tokens": cumulative_completion_tokens,
                    "cumulative_total_tokens": cumulative_prompt_tokens + cumulative_completion_tokens,
                    "tool_call_count": self._count_tool_result_messages(conversation),
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
                        result = tool_executor(func_name, func_args)
                        if previous_calls and isinstance(result, dict):
                            result = dict(result)
                            result["repeat_call_warning"] = repeat_notice

                    tool_result_message_index = len(conversation) + 1
                    conversation.append({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps(result, ensure_ascii=False),
                    })
                    tool_call_history.setdefault(signature, []).append(
                        {
                            "iteration": iterations,
                            "tool": func_name,
                            "tool_call_id": tool_id,
                            "assistant_message_index": assistant_message_index,
                            "tool_result_message_index": tool_result_message_index,
                            "arguments": func_args,
                            "blocked": bool(
                                isinstance(result, dict)
                                and result.get("repeat_call_guard")
                            ),
                            "cached_replay": bool(
                                isinstance(result, dict)
                                and result.get("cached_tool_result")
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
                    conversation.append({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": json.dumps({"error": str(e)}),
                    })
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

        if iterations >= max_iterations:
            logger.warning(f"Conversation reached max iterations ({max_iterations}). Possible loop.")
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
            self._prepare_messages_for_model(conversation)
        )
        logger.info(f"Conversation ended (truncated={iterations >= max_iterations}): {iterations} iterations, final context ≈ {final_tokens:,} tokens")
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
            "cumulative_prompt_tokens": cumulative_prompt_tokens,
            "cumulative_completion_tokens": cumulative_completion_tokens,
            "cumulative_total_tokens": cumulative_prompt_tokens + cumulative_completion_tokens,
            "tool_call_count": self._count_tool_result_messages(conversation),
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

    @staticmethod
    def _count_tool_result_messages(conversation: List[Dict[str, Any]]) -> int:
        return sum(1 for message in conversation if message.get("role") == "tool")

    @classmethod
    def _response_token_usage(
        cls,
        response: Dict[str, Any],
        prompt_messages: List[Dict[str, Any]],
        assistant_message: Dict[str, Any],
    ) -> tuple[int, int]:
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
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
                str(key): cls._normalize_tool_args(tool_name, val)
                for key, val in value.items()
            }
            if tool_name == "get_function_impl" and "max_lines" not in normalized:
                normalized["max_lines"] = 200
            if tool_name == "get_callers" and "limit" not in normalized:
                normalized["limit"] = 20
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
        result = covering_call.get("result") if isinstance(covering_call.get("result"), dict) else {}
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
    def _last_replayable_tool_result(previous_calls: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
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
                                logger.warning("Recovered tool arguments via sanitized literal_eval.")
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
