"""Built-in, answer-free provider executor for Validator replay arms.

The executor deliberately accepts only the frozen :class:`ReplayCall`.  It has
no project root, repository handle, truth path, scorer, or arbitrary prompt
hook.  A fresh ``LLMClient`` is created for every A-D invocation so one
executor invocation can represent exactly one HTTP attempt.

Arm E is intentionally not implemented here.  The product's current legacy
Validator does not expose a replay-safe session interface that both restricts
tools to frozen bundle facts and reports every provider attempt.  Using it
would make the 17M upper bound unauditable, so callers must keep using the
explicit external E adapter until that interface exists.
"""

from __future__ import annotations

import json
import logging
import marshal
import os
import re
from dataclasses import dataclass
from pathlib import Path
from types import CodeType
from typing import Any, Callable, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from ..common.validator_protocol import validator_result_schema_v3
from ..framework.conversation_recorder import get_conversation_recorder
from ..framework.llm_client import LLMClient
from .replay_bundle import canonical_json_sha256
from .validator_replay import (
    FROZEN_ACTION_SCHEMA_VERSION,
    FROZEN_QUERY_SCHEMA_VERSION,
    ReplayCall,
    ValidatorReplayError,
)


PROVIDER_CONFIG_SCHEMA_VERSION = "zscope.validator-replay-provider.v1"
BUILTIN_EXECUTOR_REVISION = 1
_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "base_url",
        "api_key_env",
        "model",
        "timeout_seconds",
        "supports_structured_output",
        "temperature",
        "transport",
    }
)
_API_KEY_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_SYSTEM_PROMPT = (
    "You are the Z-Scope Validator replay executor. Use only the supplied "
    "answer-free evidence slice. Never infer benchmark truth or request repository "
    "content. Return exactly one strict ValidatorResult v3 object. Evidence refs "
    "must be keys in evidence_ref_catalog. Missing evidence is uncertain, never an "
    "unsupported rejection."
)
_USER_PROMPT_TEMPLATE = (
    "Replay call kind={call_kind}; validation pass={validation_pass}. "
    "The following canonical JSON is the complete available input. Do not quote it "
    "in reasoning and do not request data outside it.\n\n{validator_input_json}"
)
_TERMINAL_TOOL_NAME = "emit_validator_result_v3"
_ACTION_TOOL_NAME = "emit_validator_replay_action"
_LEGACY_FORCED_FINAL_INSTRUCTION = (
    "This is the final allowed iteration (1/1). Regular tool use is now disabled. "
    "Submit the required final result by calling emit_validator_result_v3; do not "
    "ask for more tools or more turns."
)


class BuiltinReplayProviderError(ValidatorReplayError):
    """Raised when the built-in provider executor cannot preserve its contract."""


@dataclass(frozen=True)
class ReplayProviderSpec:
    """Strict, answer-free provider configuration."""

    base_url: str
    api_key_env: str
    model: str
    timeout_seconds: float
    supports_structured_output: bool
    temperature: float
    transport: str = "requests"

    def model_manifest(self) -> Dict[str, Any]:
        """Return the secret-free effective model identity."""

        return {
            "schema_version": PROVIDER_CONFIG_SCHEMA_VERSION,
            "api_protocol": "openai-compatible-stream-usage-v1",
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "model": self.model,
            "timeout_seconds": self.timeout_seconds,
            "supports_structured_output": self.supports_structured_output,
            "temperature": self.temperature,
            "transport": self.transport,
            "max_retries": 0,
            "retry_until_available": False,
            "models_per_attempt": 1,
            "base_urls_per_attempt": 1,
            "provider_usage_required": True,
        }


ClientFactory = Callable[[ReplayProviderSpec, str], Any]


def _strict_json_object(path: Path) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BuiltinReplayProviderError(f"duplicate provider config key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise BuiltinReplayProviderError(f"non-finite provider config value: {value}")

    try:
        value = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuiltinReplayProviderError("cannot load replay provider config") from exc
    if not isinstance(value, dict):
        raise BuiltinReplayProviderError("replay provider config must be a JSON object")
    return value


def load_replay_provider_spec(path: Path) -> ReplayProviderSpec:
    """Load the dedicated config without resolving or returning a secret."""

    raw = _strict_json_object(Path(path))
    if set(raw) != _CONFIG_FIELDS:
        raise BuiltinReplayProviderError("replay provider config has missing or unknown fields")
    if raw.get("schema_version") != PROVIDER_CONFIG_SCHEMA_VERSION:
        raise BuiltinReplayProviderError("replay provider config schema_version is invalid")
    base_url = raw.get("base_url")
    model = raw.get("model")
    api_key_env = raw.get("api_key_env")
    if not isinstance(base_url, str) or not base_url.strip():
        raise BuiltinReplayProviderError("replay provider base_url must be non-empty")
    parsed_url = urlsplit(base_url.strip())
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise BuiltinReplayProviderError("replay provider base_url must be HTTP(S)")
    if parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
        raise BuiltinReplayProviderError(
            "replay provider base_url must not contain credentials, a query, or a fragment"
        )
    if not isinstance(model, str) or not model.strip():
        raise BuiltinReplayProviderError("replay provider model must be non-empty")
    if not isinstance(api_key_env, str) or not _API_KEY_ENV_RE.fullmatch(api_key_env):
        raise BuiltinReplayProviderError("replay provider api_key_env is invalid")
    if "TRUTH" in api_key_env or "ANSWER" in api_key_env or "ORACLE" in api_key_env:
        raise BuiltinReplayProviderError("replay provider api_key_env is truth-bearing")
    timeout = raw.get("timeout_seconds")
    temperature = raw.get("temperature")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < float(timeout) <= 3600
    ):
        raise BuiltinReplayProviderError("timeout_seconds must be in (0, 3600]")
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not 0 <= float(temperature) <= 2
    ):
        raise BuiltinReplayProviderError("temperature must be in [0, 2]")
    structured = raw.get("supports_structured_output")
    if not isinstance(structured, bool):
        raise BuiltinReplayProviderError("supports_structured_output must be boolean")
    if raw.get("transport") != "requests":
        raise BuiltinReplayProviderError(
            "formal replay provider transport must be exactly 'requests'"
        )
    return ReplayProviderSpec(
        base_url=base_url.strip().rstrip("/"),
        api_key_env=api_key_env,
        model=model.strip(),
        timeout_seconds=float(timeout),
        supports_structured_output=structured,
        temperature=float(temperature),
        transport="requests",
    )


def _terminal_tool_schema() -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": _TERMINAL_TOOL_NAME,
            "description": "Emit one strict Z-Scope ValidatorResult v3 object.",
            "parameters": validator_result_schema_v3(),
        },
    }


def _investigation_action_schema() -> Dict[str, Any]:
    query_schema = {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string", "enum": [FROZEN_QUERY_SCHEMA_VERSION]},
            "query_kind": {
                "type": "string",
                "enum": ["fact_by_kind", "fact_by_uid", "evidence_by_key"],
            },
            "key": {"type": "string", "minLength": 1, "maxLength": 512},
            "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
        "required": ["schema_version", "query_kind", "key", "reason"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string", "enum": [FROZEN_ACTION_SCHEMA_VERSION]},
            "action": {"type": "string", "enum": ["query", "terminal"]},
            "query": {"anyOf": [query_schema, {"type": "null"}]},
            "result": {"anyOf": [validator_result_schema_v3(), {"type": "null"}]},
        },
        "required": ["schema_version", "action", "query", "result"],
        "additionalProperties": False,
    }


def _action_tool_schema() -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": _ACTION_TOOL_NAME,
            "description": (
                "Request one frozen read-only lookup or emit the terminal investigation result."
            ),
            "parameters": _investigation_action_schema(),
        },
    }


def _prompt_manifest(spec: ReplayProviderSpec) -> Dict[str, Any]:
    return {
        "prompt_revision": 1,
        "system_prompt": _SYSTEM_PROMPT,
        "user_prompt_template": _USER_PROMPT_TEMPLATE,
        "result_schema": validator_result_schema_v3(),
        "response_transport_by_protocol": {
            "legacy_single_turn_bridge": "generic_loop_terminal_tool_without_forced_choice",
            "v3_bounded": (
                "strict_json_schema"
                if spec.supports_structured_output
                else "required_terminal_tool"
            ),
        },
        # Arm A always exposes this terminal bridge even when B-D use native
        # structured output, so it must always be part of the prompt identity.
        "terminal_tool_schema": _terminal_tool_schema(),
        "legacy_forced_final_instruction": _LEGACY_FORCED_FINAL_INSTRUCTION,
        "investigation_action_schema": _investigation_action_schema(),
        "investigation_action_tool_schema": (
            None if spec.supports_structured_output else _action_tool_schema()
        ),
    }


def _stable_code_payload(code: CodeType) -> Dict[str, Any]:
    """Fingerprint loaded bytecode without reading the source checkout.

    ``marshal`` is used only for non-code constants.  Filenames, line tables,
    and absolute installation paths are intentionally excluded.
    """

    constants: list[Any] = []
    for value in code.co_consts:
        if isinstance(value, CodeType):
            constants.append(_stable_code_payload(value))
        elif isinstance(value, (str, bytes, int, float, complex, bool, type(None), tuple)):
            constants.append(marshal.dumps(value).hex())
        else:
            constants.append(repr(type(value)))
    return {
        "argcount": code.co_argcount,
        "posonlyargcount": code.co_posonlyargcount,
        "kwonlyargcount": code.co_kwonlyargcount,
        "flags": code.co_flags,
        "code": code.co_code.hex(),
        "consts": constants,
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
    }


def _code_sha256(functions: Sequence[Callable[..., Any]]) -> str:
    return str(canonical_json_sha256([_stable_code_payload(fn.__code__) for fn in functions]))


def derive_builtin_execution_identity(spec: ReplayProviderSpec) -> Dict[str, str]:
    """Derive all identity fields from loaded code, config, and prompt templates."""

    model_spec_sha256 = canonical_json_sha256(spec.model_manifest())
    prompt_sha256 = canonical_json_sha256(_prompt_manifest(spec))
    implementation_sha256 = _code_sha256(
        (
            BuiltinProviderReplayExecutor.execute,
            BuiltinProviderReplayExecutor._messages,
            BuiltinProviderReplayExecutor._completion_kwargs,
            BuiltinProviderReplayExecutor._validate_request_shape,
            BuiltinProviderReplayExecutor._result,
            BuiltinProviderReplayExecutor._schema_and_tool_name,
            BuiltinProviderReplayExecutor._usage,
            _default_client_factory,
            LLMClient.chat_completion,
            LLMClient._normalized_provider_usage,
        )
    )
    executor_sha256 = canonical_json_sha256(
        {
            "executor": "zscope.builtin-validator-replay-provider",
            "revision": BUILTIN_EXECUTOR_REVISION,
            "implementation_sha256": implementation_sha256,
            "model_spec_sha256": model_spec_sha256,
            "prompt_sha256": prompt_sha256,
            "input_scope": "ReplayCall.answer_free_only",
            "a_d_invocation_scope": "one_fresh_client_one_http_attempt",
            "arm_e": "fail_closed_external_adapter_required",
            "dependency_binding": (
                "selected_loaded_bytecode_here; complete dependency closure is bound by "
                "the formal scanner bundle and git SHA"
            ),
        }
    )
    return {
        "executor_sha256": executor_sha256,
        "model_spec_sha256": model_spec_sha256,
        "prompt_sha256": prompt_sha256,
    }


def _default_client_factory(spec: ReplayProviderSpec, api_key: str) -> LLMClient:
    client = LLMClient(
        api_key=api_key,
        base_url=spec.base_url,
        models=[spec.model],
        timeout=spec.timeout_seconds,
        max_retries=0,
        retry_until_available=False,
        max_tokens=8192,
        base_url_max_concurrent_requests=1,
        global_max_concurrent_requests=1,
        supports_structured_output=spec.supports_structured_output,
        token_usage_ledger=None,
        llm_ref="validator_replay_builtin",
    )
    # LLMClient reads this process-wide option at construction.  Formal replay
    # fixes requests transport in the dedicated config, independent of ambient
    # developer settings.
    client._transport = "requests"
    return client


class BuiltinProviderReplayExecutor:
    """One-attempt real-provider executor for answer-free replay arms A-D."""

    def __init__(
        self,
        spec: ReplayProviderSpec,
        api_key: str,
        *,
        client_factory: ClientFactory = _default_client_factory,
    ) -> None:
        if not api_key:
            raise BuiltinReplayProviderError(
                f"replay provider API key environment variable {spec.api_key_env!r} is empty"
            )
        self.spec = spec
        self._api_key = api_key
        self._client_factory = client_factory
        self.execution_identity = derive_builtin_execution_identity(spec)

    @classmethod
    def from_config(
        cls,
        path: Path,
        *,
        environment: Optional[Mapping[str, str]] = None,
        client_factory: ClientFactory = _default_client_factory,
    ) -> "BuiltinProviderReplayExecutor":
        spec = load_replay_provider_spec(path)
        environ = os.environ if environment is None else environment
        api_key = str(environ.get(spec.api_key_env) or "")
        return cls(spec, api_key, client_factory=client_factory)

    def execute(self, call: ReplayCall) -> Mapping[str, Any]:
        if call.arm_id == "E" or call.protocol_mode == "legacy_multi_turn_upper_bound":
            raise BuiltinReplayProviderError(
                "Arm E has no replay-safe built-in legacy session executor; use the "
                "explicit external --executor adapter"
            )
        if call.arm_id not in {"A", "B", "C", "D"}:
            raise BuiltinReplayProviderError("built-in replay executor supports A-D only")
        if get_conversation_recorder() is not None:
            raise BuiltinReplayProviderError(
                "conversation recording must be disabled for answer-free provider replay"
            )
        client = self._client_factory(self.spec, self._api_key)
        chat_completion = getattr(client, "chat_completion", None)
        if not callable(chat_completion):
            raise BuiltinReplayProviderError("provider client has no chat_completion method")
        messages = self._messages(call)
        kwargs = self._completion_kwargs(call)
        self._validate_request_shape(call, messages, kwargs)
        # LLMClient intentionally logs provider error bodies in normal product
        # operation.  A replay endpoint could echo request content in such a
        # body, so formal replay suppresses that logger for the one isolated
        # attempt.  Usage remains fully represented by the returned ledger.
        provider_logger = logging.getLogger("zscope.framework.llm_client")
        logger_was_disabled = provider_logger.disabled
        provider_logger.disabled = True
        try:
            response = chat_completion(
                messages,
                **kwargs,
            )
        finally:
            provider_logger.disabled = logger_was_disabled
        if not isinstance(response, Mapping):
            raise BuiltinReplayProviderError("provider response must be an object")
        return {
            "result": self._result(response, call),
            "usage": self._usage(response),
            "execution_identity": dict(self.execution_identity),
        }

    @staticmethod
    def _validate_request_shape(
        call: ReplayCall,
        messages: Sequence[Mapping[str, Any]],
        kwargs: Mapping[str, Any],
    ) -> None:
        """Validate protocol framing without applying a scan-wide token gate."""

        max_output = call.limits.get("effective_max_output_tokens")
        if isinstance(max_output, bool) or not isinstance(max_output, int) or max_output <= 0:
            raise BuiltinReplayProviderError("built-in provider output limit is invalid")
        wire_projection = {
            "messages": list(messages),
            "tools": kwargs.get("tools"),
            "tool_choice": kwargs.get("tool_choice"),
            "response_format": kwargs.get("response_format"),
            "temperature": kwargs.get("temperature"),
            "model": "<bound-by-model-spec>",
        }
        estimated_input = LLMClient.estimate_tokens(
            [
                {
                    "role": "user",
                    "content": json.dumps(
                        wire_projection,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ),
                }
            ]
        )
        if estimated_input <= 0:
            raise BuiltinReplayProviderError("built-in provider request projection is empty")

    def _messages(self, call: ReplayCall) -> list[Dict[str, Any]]:
        canonical_input = json.dumps(
            call.validator_input,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _USER_PROMPT_TEMPLATE.format(
                    call_kind=call.call_kind,
                    validation_pass=call.validation_pass,
                    validator_input_json=canonical_input,
                ),
            },
        ]
        if call.call_kind == "legacy_forced_final":
            # This is the exact terminal bridge injected by the generic loop
            # when max_iterations=1 and a terminal tool is required.
            messages.append({"role": "user", "content": _LEGACY_FORCED_FINAL_INSTRUCTION})
        return messages

    @staticmethod
    def _schema_and_tool_name(call: ReplayCall) -> tuple[Dict[str, Any], str]:
        if call.call_kind == "bounded_investigation_turn":
            return _investigation_action_schema(), _ACTION_TOOL_NAME
        return validator_result_schema_v3(), _TERMINAL_TOOL_NAME

    def _completion_kwargs(self, call: ReplayCall) -> Dict[str, Any]:
        schema, tool_name = self._schema_and_tool_name(call)
        kwargs: Dict[str, Any] = {
            "temperature": self.spec.temperature,
            "max_tokens": int(call.limits["effective_max_output_tokens"]),
            "trace_agent": "validator_replay_builtin",
            "trace_label": (
                f"answer_free_replay; arm={call.arm_id}; call_kind={call.call_kind}; "
                f"pass={call.validation_pass}"
            ),
            "trace_iteration": 1,
        }
        if self.spec.supports_structured_output and call.call_kind != "legacy_forced_final":
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": (
                        "validator_replay_action"
                        if call.call_kind == "bounded_investigation_turn"
                        else "validator_result_v3"
                    ),
                    "strict": True,
                    "schema": schema,
                },
            }
        else:
            kwargs["tools"] = [
                (
                    _action_tool_schema()
                    if call.call_kind == "bounded_investigation_turn"
                    else _terminal_tool_schema()
                )
            ]
            # The frozen Arm A bridge mirrors LLMClient.run_conversation_loop:
            # on its last iteration the generic loop passes only the terminal
            # schema but does not add a tool_choice argument. B-D's fallback
            # protocol, by contrast, requires their sole terminal tool.
            if call.call_kind != "legacy_forced_final":
                kwargs["tool_choice"] = {
                    "type": "function",
                    "function": {"name": tool_name},
                }
        return kwargs

    def _result(self, response: Mapping[str, Any], call: ReplayCall) -> Any:
        choices = response.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            return {"protocol_error": "provider_choice_count"}
        choice = choices[0]
        if not isinstance(choice, Mapping):
            return {"protocol_error": "provider_choice_shape"}
        message = choice.get("message")
        if not isinstance(message, Mapping):
            return {"protocol_error": "provider_message_shape"}
        if self.spec.supports_structured_output and call.call_kind != "legacy_forced_final":
            content = message.get("content")
            if not isinstance(content, str):
                return {"protocol_error": "missing_structured_content"}
            try:
                value = json.loads(content)
            except (ValueError, TypeError):
                return {"protocol_error": "malformed_structured_content"}
            return value if isinstance(value, Mapping) else {"protocol_error": "non_object_result"}
        tool_calls = message.get("tool_calls")
        if not isinstance(tool_calls, list) or len(tool_calls) != 1:
            return {"protocol_error": "terminal_tool_count"}
        tool_call = tool_calls[0]
        function = tool_call.get("function") if isinstance(tool_call, Mapping) else None
        _schema, expected_tool_name = self._schema_and_tool_name(call)
        if not isinstance(function, Mapping) or function.get("name") != expected_tool_name:
            return {"protocol_error": "terminal_tool_name"}
        arguments = function.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                return {"protocol_error": "malformed_terminal_arguments"}
        return (
            arguments
            if isinstance(arguments, Mapping)
            else {"protocol_error": "terminal_arguments_shape"}
        )

    @staticmethod
    def _usage(response: Mapping[str, Any]) -> Dict[str, Any]:
        raw = response.get("usage")
        if not isinstance(raw, Mapping) or raw.get("estimated") is not False:
            raise BuiltinReplayProviderError("provider did not return authoritative usage")

        def token(field: str) -> int:
            value = raw.get(field, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise BuiltinReplayProviderError(f"provider usage.{field} is invalid")
            return int(value)

        prompt = token("prompt_tokens")
        completion = token("completion_tokens")
        total = token("total_tokens")
        cached = token("cached_prompt_tokens")
        reasoning = token("reasoning_tokens")
        if total != prompt + completion:
            raise BuiltinReplayProviderError("provider usage total is not prompt+completion")
        if cached > prompt or reasoning > completion:
            raise BuiltinReplayProviderError("provider usage subset counters are invalid")
        tool_call_count = 0
        choices = response.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                message = choice.get("message") if isinstance(choice, Mapping) else None
                tool_calls = message.get("tool_calls") if isinstance(message, Mapping) else None
                if isinstance(tool_calls, list):
                    tool_call_count += len(tool_calls)
        return {
            "prompt_tokens": prompt,
            "cached_prompt_tokens": cached,
            "completion_tokens": completion,
            "reasoning_tokens": reasoning,
            "total_tokens": total,
            "tool_call_count": tool_call_count,
            "api_attempt_count": 1,
            "provider_reported": True,
        }


def assert_expected_builtin_identity(
    executor: BuiltinProviderReplayExecutor,
    expected: Mapping[str, str],
) -> None:
    """Require an externally frozen identity; never trust caller self-reporting."""

    if set(expected) != set(executor.execution_identity):
        raise BuiltinReplayProviderError("expected built-in identity fields are invalid")
    mismatched = [
        field
        for field in sorted(executor.execution_identity)
        if str(expected.get(field) or "") != executor.execution_identity[field]
    ]
    if mismatched:
        raise BuiltinReplayProviderError(
            "built-in replay identity does not match externally expected " + ", ".join(mismatched)
        )


__all__ = [
    "BUILTIN_EXECUTOR_REVISION",
    "PROVIDER_CONFIG_SCHEMA_VERSION",
    "BuiltinProviderReplayExecutor",
    "BuiltinReplayProviderError",
    "ReplayProviderSpec",
    "assert_expected_builtin_identity",
    "derive_builtin_execution_identity",
    "load_replay_provider_spec",
]
