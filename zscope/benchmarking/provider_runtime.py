"""Frozen provider identity and explicit benchmark credential-file handling.

This module deliberately does not discover or load a local environment file on
its own.  Callers must supply the exact path they intend to trust.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml

from zscope.framework.provider_failure_marker import (
    P6_PROVIDER_FAILURE_CONTAINER_PATH,
    P6_PROVIDER_FAILURE_FILENAME,
    P6_PROVIDER_FAILURE_SCHEMA_VERSION,
    write_p6_provider_failure_marker,
)


PROVIDER_RUNTIME_CONTRACT_VERSION = "zscope.provider-runtime-contract.v1"
P6_API_KEY_ENVIRONMENT_KEY = "Z_SCOPE_API_KEY"
PROVIDER_BASE_URL_ENVIRONMENT_KEY = "Z_SCOPE_LLM_BASE_URL"
PROVIDER_MODEL_ENVIRONMENT_KEY = "Z_SCOPE_LLM_MODEL"
P6_PROVIDER_BASE_URL = "https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1"
P6_PROVIDER_MODEL = "GLM-5.2"
P6_MAX_CONCURRENT_CALLS = 8

_ENV_REFERENCE_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_ENV_ASSIGNMENT_RE = re.compile(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\Z")

PROVIDER_FAILURE_CLASSES = frozenset(
    {
        "provider_credentials_unavailable",
        "provider_transport_exhausted",
        "provider_usage_unverifiable",
        "provider_identity_mismatch",
        "provider_protocol_incompatible",
    }
)
_PROVIDER_RUNTIME_FAILURE_CLASSES = PROVIDER_FAILURE_CLASSES | {
    "provider_identity_override_attempt",
    "internal_failure",
}


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""

    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> Any:
        self.flatten_mapping(node)
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _strict_yaml_load(payload: str) -> Any:
    return yaml.load(payload, Loader=_StrictSafeLoader)


class ProviderRuntimeError(ValueError):
    """Raised when a benchmark provider identity or credential boundary fails."""

    def __init__(self, message: str, *, failure_class: str | None = None) -> None:
        if failure_class is not None and failure_class not in _PROVIDER_RUNTIME_FAILURE_CLASSES:
            raise ValueError("unsupported provider runtime failure class")
        self.failure_class = failure_class
        super().__init__(message)


class ProviderProbeError(ProviderRuntimeError):
    """Answer-free provider failure with a fixed externally reportable class."""

    def __init__(self, failure_class: str) -> None:
        super().__init__("provider probe failed", failure_class=failure_class)


class _DuplicateJsonKeyError(ValueError):
    """Internal marker for ambiguous provider JSON objects."""


def _reject_duplicate_json_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKeyError("duplicate provider JSON key")
        value[key] = item
    return value


def _reject_non_finite_json(value: str) -> Any:
    raise ValueError("non-finite JSON value")


def load_p6_provider_failure_marker(path: Path) -> dict[str, Any]:
    """Read a candidate-produced marker without trusting links or free text."""

    target = Path(path)
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise ProviderRuntimeError("P6 provider failure marker is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProviderRuntimeError("P6 provider failure marker type is invalid")
    if metadata.st_size <= 0 or metadata.st_size > 1024:
        raise ProviderRuntimeError("P6 provider failure marker size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size <= 0
                or opened.st_size > 1024
            ):
                raise ProviderRuntimeError("P6 provider failure marker changed during read")
            raw = bytearray()
            while len(raw) <= 1024:
                chunk = os.read(descriptor, min(1025 - len(raw), 1024))
                if not chunk:
                    break
                raw.extend(chunk)
            completed = os.fstat(descriptor)
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if len(raw) > 1024 or any(
                getattr(opened, name, None) != getattr(completed, name, None)
                for name in stable_fields
                if hasattr(opened, name) and hasattr(completed, name)
            ):
                raise ProviderRuntimeError("P6 provider failure marker changed during read")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ProviderRuntimeError("P6 provider failure marker read failed") from exc
    try:
        value = json.loads(
            bytes(raw).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_non_finite_json,
        )
    except (UnicodeError, json.JSONDecodeError, _DuplicateJsonKeyError, ValueError) as exc:
        raise ProviderRuntimeError("P6 provider failure marker JSON is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "failure_class", "failure_count"}
        or value.get("schema_version") != P6_PROVIDER_FAILURE_SCHEMA_VERSION
        or value.get("failure_class") not in PROVIDER_FAILURE_CLASSES
        or type(value.get("failure_count")) is not int
        or value.get("failure_count") != 1
    ):
        raise ProviderRuntimeError("P6 provider failure marker contract is invalid")
    return value


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_config_snapshot(path: Path) -> tuple[Any, str]:
    """Read one immutable, no-follow config snapshot for parsing and hashing."""

    target = Path(path)
    try:
        metadata = target.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ProviderRuntimeError("benchmark provider config must not be a symbolic link")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise ProviderRuntimeError("benchmark provider config is unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ProviderRuntimeError("benchmark provider config must be a regular file")
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            raise ProviderRuntimeError("benchmark provider config changed during validation")
        if opened.st_size > 8 * 1024 * 1024:
            raise ProviderRuntimeError("benchmark provider config exceeds the size limit")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > 8 * 1024 * 1024:
                raise ProviderRuntimeError("benchmark provider config exceeds the size limit")
        completed = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(opened, name, None) != getattr(completed, name, None)
            for name in stable_fields
            if hasattr(opened, name) and hasattr(completed, name)
        ):
            raise ProviderRuntimeError("benchmark provider config changed during validation")
    except OSError as exc:
        raise ProviderRuntimeError("benchmark provider config is unreadable") from exc
    finally:
        os.close(descriptor)
    frozen = bytes(payload)
    try:
        raw = _strict_yaml_load(frozen.decode("utf-8-sig"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ProviderRuntimeError("benchmark provider config is unreadable") from exc
    return raw, hashlib.sha256(frozen).hexdigest()


def _environment_references(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        return {name for nested in value.values() for name in _environment_references(nested)}
    if isinstance(value, (list, tuple)):
        return {name for nested in value for name in _environment_references(nested)}
    if not isinstance(value, str):
        return set()
    return {str(match.group(1) or match.group(2)) for match in _ENV_REFERENCE_RE.finditer(value)}


def required_environment_keys(config_path: Path) -> tuple[str, ...]:
    """Return only environment keys referenced by a benchmark YAML value."""

    raw, _config_sha256 = _read_config_snapshot(Path(config_path))
    if not isinstance(raw, Mapping):
        raise ProviderRuntimeError("benchmark provider config must be an object")
    return tuple(sorted(_environment_references(raw)))


def _single_provider_value(values: Any, *, field: str) -> str:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ProviderRuntimeError(f"benchmark provider {field} must be a list")
    normalized = [str(value).strip() for value in values if str(value).strip()]
    if len(normalized) != 1:
        raise ProviderRuntimeError(
            f"benchmark provider {field} must contain exactly one frozen value"
        )
    return normalized[0]


@dataclass(frozen=True)
class ProviderRuntimeContract:
    """Content-bound provider identity used by the runner and OCI boundary."""

    base_url: str
    model: str
    config_sha256: str
    required_environment_keys: tuple[str, ...]
    identity_sha256: str
    schema_version: str = PROVIDER_RUNTIME_CONTRACT_VERSION

    @classmethod
    def from_config_file(cls, config_path: Path) -> "ProviderRuntimeContract":
        path = Path(config_path)
        raw, config_sha256 = _read_config_snapshot(path)
        return cls._from_frozen_config(raw, config_sha256=config_sha256)

    @classmethod
    def _from_frozen_config(
        cls,
        raw: Any,
        *,
        config_sha256: str,
    ) -> "ProviderRuntimeContract":
        if not isinstance(raw, Mapping):
            raise ProviderRuntimeError("benchmark provider config must be an object")
        profiles = raw.get("llms")
        profile = profiles.get("default") if isinstance(profiles, Mapping) else None
        if not isinstance(profile, Mapping):
            raise ProviderRuntimeError("benchmark provider default profile is missing")
        base_url = _single_provider_value(profile.get("base_urls"), field="base_urls").rstrip("/")
        model = _single_provider_value(profile.get("models"), field="models")
        if _environment_references(base_url) or _environment_references(model):
            raise ProviderRuntimeError("benchmark provider identity must be source-controlled")
        keys = tuple(sorted(_environment_references(raw)))
        identity_payload = {
            "schema_version": PROVIDER_RUNTIME_CONTRACT_VERSION,
            "base_url": base_url,
            "model": model,
            "config_sha256": config_sha256,
            "required_environment_keys": list(keys),
        }
        return cls(
            base_url=base_url,
            model=model,
            config_sha256=config_sha256,
            required_environment_keys=keys,
            identity_sha256=_canonical_sha256(identity_payload),
        )

    @classmethod
    def from_effective_config(
        cls,
        effective: Any,
        *,
        config_path: Path,
        required_keys: Sequence[str] | None = None,
    ) -> "ProviderRuntimeContract":
        profile = getattr(effective, "llm", None)
        if profile is None:
            profiles = getattr(effective, "llms", None)
            if isinstance(profiles, Mapping):
                profile = profiles.get("default")
        if profile is None:
            raise ProviderRuntimeError("benchmark provider default profile is missing")
        base_url = _single_provider_value(
            getattr(profile, "base_urls", None), field="base_urls"
        ).rstrip("/")
        model = _single_provider_value(getattr(profile, "models", None), field="models")
        if not base_url or not model:
            raise ProviderRuntimeError("benchmark provider identity is incomplete")
        raw, config_sha256 = _read_config_snapshot(Path(config_path))
        if not isinstance(raw, Mapping):
            raise ProviderRuntimeError("benchmark provider config must be an object")
        keys = tuple(
            sorted(
                set(required_keys) if required_keys is not None else _environment_references(raw)
            )
        )
        identity_payload = {
            "schema_version": PROVIDER_RUNTIME_CONTRACT_VERSION,
            "base_url": base_url,
            "model": model,
            "config_sha256": config_sha256,
            "required_environment_keys": list(keys),
        }
        return cls(
            base_url=base_url,
            model=model,
            config_sha256=config_sha256,
            required_environment_keys=keys,
            identity_sha256=_canonical_sha256(identity_payload),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "base_url": self.base_url,
            "model": self.model,
            "config_sha256": self.config_sha256,
            "required_environment_keys": list(self.required_environment_keys),
            "identity_sha256": self.identity_sha256,
        }


def require_p6_provider_contract(config_path: Path) -> ProviderRuntimeContract:
    """Fail closed unless the source-controlled P6 provider contract is exact.

    ``ProviderRuntimeContract`` intentionally remains generic for other bundled
    benchmarks.  Pilot mode uses this stricter entry point so a valid-looking
    source-controlled config cannot silently select a different deployment,
    alias, secret set, or concurrency policy.
    """

    raw, config_sha256 = _read_config_snapshot(Path(config_path))
    contract = ProviderRuntimeContract._from_frozen_config(
        raw,
        config_sha256=config_sha256,
    )
    if not isinstance(raw, Mapping):
        raise ProviderRuntimeError(
            "provider_identity_mismatch",
            failure_class="provider_identity_mismatch",
        )
    profiles = raw.get("llms")
    profile = profiles.get("default") if isinstance(profiles, Mapping) else None
    concurrency = raw.get("concurrency")
    scan = raw.get("scan")
    selected_profiles = scan.get("llm_profiles") if isinstance(scan, Mapping) else None
    if selected_profiles is None:
        selected_profiles = {}
    if (
        contract.base_url != P6_PROVIDER_BASE_URL
        or contract.model != P6_PROVIDER_MODEL
        or contract.required_environment_keys != (P6_API_KEY_ENVIRONMENT_KEY,)
        or not isinstance(profile, Mapping)
        or not isinstance(profiles, Mapping)
        or set(profiles) != {"default"}
        or not isinstance(selected_profiles, Mapping)
        or set(selected_profiles) - {"modeling", "analysis", "validation"}
        or any(
            selected_profiles.get(role, "default") != "default"
            for role in ("modeling", "analysis", "validation")
        )
        or profile.get("api_key") != "${Z_SCOPE_API_KEY}"
        or profile.get("base_url_max_concurrent_requests") != P6_MAX_CONCURRENT_CALLS
        or type(profile.get("max_tokens")) is not int
        or profile.get("max_tokens") != 8192
        or type(profile.get("max_retries")) is not int
        or profile.get("max_retries") != 2
        or profile.get("retry_until_available") is not False
        or profile.get("require_exact_response_model") is not True
        or type(profile.get("timeout")) is not int
        or profile.get("timeout") != 120
        or not isinstance(concurrency, Mapping)
        or concurrency.get("llm_max_inflight") != P6_MAX_CONCURRENT_CALLS
    ):
        raise ProviderRuntimeError(
            "provider_identity_mismatch",
            failure_class="provider_identity_mismatch",
        )
    return contract


def reject_conflicting_provider_identity_environment(
    contract: ProviderRuntimeContract,
    environment: Mapping[str, str],
) -> None:
    """Reject legacy identity variables that try to override a fixed contract."""

    required = set(contract.required_environment_keys)
    legacy_base_url = str(environment.get(PROVIDER_BASE_URL_ENVIRONMENT_KEY) or "").strip()
    legacy_model = str(environment.get(PROVIDER_MODEL_ENVIRONMENT_KEY) or "").strip()
    if (
        PROVIDER_BASE_URL_ENVIRONMENT_KEY not in required
        and legacy_base_url
        and legacy_base_url.rstrip("/") != contract.base_url
    ) or (
        PROVIDER_MODEL_ENVIRONMENT_KEY not in required
        and legacy_model
        and legacy_model != contract.model
    ):
        raise ProviderRuntimeError(
            "provider_identity_override_attempt",
            failure_class="provider_identity_override_attempt",
        )


def load_explicit_api_key_file(path: Path) -> dict[str, str]:
    """Validate and load an explicitly selected one-key private env file.

    The returned mapping is intended for immediate child-process construction;
    callers must not persist it to process-global environment or artifacts.
    """

    target = Path(path)
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise ProviderRuntimeError("provider_credentials_unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ProviderRuntimeError("provider credential file must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise ProviderRuntimeError("provider_credentials_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ProviderRuntimeError("provider credential file must be a regular file")
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            raise ProviderRuntimeError("provider credential file changed during validation")
        if stat.S_IMODE(opened.st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
            raise ProviderRuntimeError("provider credential file permissions are too broad")
        if opened.st_size > 1024 * 1024:
            raise ProviderRuntimeError("provider credential file exceeds the size limit")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > 1024 * 1024:
                raise ProviderRuntimeError("provider credential file exceeds the size limit")
        completed = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(opened, name, None) != getattr(completed, name, None)
            for name in stable_fields
            if hasattr(opened, name) and hasattr(completed, name)
        ):
            raise ProviderRuntimeError("provider credential file changed during validation")
    except OSError as exc:
        raise ProviderRuntimeError("provider_credentials_unavailable") from exc
    finally:
        os.close(descriptor)
    try:
        decoded = bytes(payload).decode("utf-8-sig")
    except UnicodeError as exc:
        raise ProviderRuntimeError("provider_credentials_unavailable") from exc
    if any(ord(character) < 32 and character not in {"\t", "\r", "\n"} for character in decoded):
        raise ProviderRuntimeError("provider credential file contains control characters")
    lines = decoded.splitlines()

    loaded: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_ASSIGNMENT_RE.fullmatch(line)
        if match is None:
            raise ProviderRuntimeError(
                f"invalid provider credential assignment at line {line_number}"
            )
        key = match.group(1)
        if key != P6_API_KEY_ENVIRONMENT_KEY:
            raise ProviderRuntimeError(f"unexpected provider credential key: {key}")
        if key in loaded:
            raise ProviderRuntimeError(f"duplicate provider credential key: {key}")
        value = match.group(2).strip()
        quote_count = value.count("'") + value.count('"')
        if quote_count:
            if (
                len(value) < 2
                or value[0] not in {"'", '"'}
                or value[-1] != value[0]
                or any(character in {"'", '"'} for character in value[1:-1])
            ):
                raise ProviderRuntimeError("provider API key quoting is invalid")
            value = value[1:-1]
        if not value:
            raise ProviderRuntimeError("provider API key must not be empty")
        if len(value.encode("utf-8")) > 16 * 1024:
            raise ProviderRuntimeError("provider API key exceeds the size limit")
        loaded[key] = value
    if set(loaded) != {P6_API_KEY_ENVIRONMENT_KEY}:
        raise ProviderRuntimeError("provider_credentials_unavailable")
    return loaded


@dataclass(frozen=True)
class ProviderProbeResponse:
    status: int
    body: bytes


ProviderProbeTransport = Callable[[Request, float], ProviderProbeResponse]


class _RejectRedirects(HTTPRedirectHandler):
    """Keep the bearer credential on the one frozen provider origin."""

    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _provider_probe_transport(request: Request, timeout: float) -> ProviderProbeResponse:
    try:
        # urllib's default redirect handler can copy Authorization from a POST
        # onto a redirected request.  The P6 probe is bound to one exact
        # endpoint, so every 3xx is a protocol failure and must never be
        # followed.
        with build_opener(_RejectRedirects()).open(
            request, timeout=timeout
        ) as response:  # nosec B310 - frozen HTTPS config, redirects disabled
            body = response.read(1024 * 1024 + 1)
            status = int(getattr(response, "status", 200))
    except HTTPError as exc:
        status = int(exc.code)
        body = b""
    except (TimeoutError, socket.timeout, URLError, OSError) as exc:
        raise ProviderProbeError("provider_transport_exhausted") from exc
    return ProviderProbeResponse(status=status, body=body)


def _probe_http_failure_class(status: int) -> str:
    if status in {401, 403}:
        return "provider_credentials_unavailable"
    if status == 429 or 500 <= status <= 599:
        return "provider_transport_exhausted"
    return "provider_protocol_incompatible"


def probe_provider(
    contract: ProviderRuntimeContract,
    *,
    api_key: str,
    timeout: float = 120.0,
    transport: ProviderProbeTransport = _provider_probe_transport,
) -> dict[str, Any]:
    """Make one constant, source-free provider request and retain no response text."""

    if not api_key:
        raise ProviderProbeError("provider_credentials_unavailable")
    request_payload = {
        "model": contract.model,
        "messages": [
            {
                "role": "user",
                "content": "Return a JSON object with the single boolean field ok set to true.",
            }
        ],
        "max_tokens": 32,
        "stream": False,
        "temperature": 0,
    }
    request = Request(
        contract.base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(request_payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    response = transport(request, timeout)
    if not 200 <= response.status <= 299:
        raise ProviderProbeError(_probe_http_failure_class(response.status))
    if len(response.body) > 1024 * 1024:
        raise ProviderProbeError("provider_protocol_incompatible")
    try:
        payload = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, _DuplicateJsonKeyError) as exc:
        raise ProviderProbeError("provider_protocol_incompatible") from exc
    if not isinstance(payload, Mapping):
        raise ProviderProbeError("provider_protocol_incompatible")
    if payload.get("model") != contract.model:
        raise ProviderProbeError("provider_identity_mismatch")
    usage = payload.get("usage")
    prompt_tokens = usage.get("prompt_tokens") if isinstance(usage, Mapping) else None
    completion_tokens = usage.get("completion_tokens") if isinstance(usage, Mapping) else None
    total_tokens = usage.get("total_tokens") if isinstance(usage, Mapping) else None
    if any(
        not isinstance(item, int) or isinstance(item, bool) or item < 0
        for item in (prompt_tokens, completion_tokens, total_tokens)
    ):
        raise ProviderProbeError("provider_usage_unverifiable")
    assert isinstance(prompt_tokens, int)
    assert isinstance(completion_tokens, int)
    assert isinstance(total_tokens, int)
    if total_tokens != prompt_tokens + completion_tokens:
        raise ProviderProbeError("provider_usage_unverifiable")
    choices = payload.get("choices")
    if (
        not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], Mapping)
        or choices[0].get("finish_reason") != "stop"
    ):
        raise ProviderProbeError("provider_protocol_incompatible")
    message = choices[0].get("message")
    content = message.get("content") if isinstance(message, Mapping) else None
    if not isinstance(content, str) or len(content.encode("utf-8")) > 1024:
        raise ProviderProbeError("provider_protocol_incompatible")
    try:
        neutral_result = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (json.JSONDecodeError, _DuplicateJsonKeyError) as exc:
        raise ProviderProbeError("provider_protocol_incompatible") from exc
    if neutral_result != {"ok": True}:
        raise ProviderProbeError("provider_protocol_incompatible")
    conservation = {
        "physical_call_count": 1,
        "provider_reported_call_count": 1,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": contract.model,
        "requested_model_coverage": 1.0,
        "response_model": contract.model,
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            "token": {
                "numerator": total_tokens,
                "denominator": total_tokens,
                "conserved": True,
            },
            **{
                name: {"numerator": 0, "denominator": 0, "conserved": True}
                for name in ("tool", "trace", "finding", "terminal")
            },
        },
    }
    return {
        "schema_version": "zscope.p6-provider-probe.v1",
        "stage": "provider",
        "passed": True,
        "call_count": 1,
        "provider_usage_coverage": 1.0,
        "estimated_provider_call_count": 0,
        "provider_identity_sha256": contract.identity_sha256,
        "config_sha256": contract.config_sha256,
        "model": contract.model,
        "usage_conservation": conservation,
    }


def run_p6_provider_probe(
    config_path: Path,
    *,
    environment: Mapping[str, str] | None = None,
    transport: ProviderProbeTransport = _provider_probe_transport,
) -> dict[str, Any]:
    """Load the explicit P6 key file and execute the constant neutral probe."""

    source = environment if environment is not None else os.environ
    path_value = str(source.get("Z_SCOPE_P6_API_KEY_FILE") or "").strip()
    if not path_value:
        raise ProviderProbeError("provider_credentials_unavailable")
    key_path = Path(path_value)
    if not key_path.is_absolute():
        raise ProviderProbeError("provider_credentials_unavailable")
    try:
        credentials = load_explicit_api_key_file(key_path)
    except ProviderRuntimeError as exc:
        raise ProviderProbeError("provider_credentials_unavailable") from exc
    try:
        contract = require_p6_provider_contract(config_path)
    except ProviderRuntimeError as exc:
        raise ProviderProbeError("provider_identity_mismatch") from exc
    try:
        reject_conflicting_provider_identity_environment(contract, source)
    except ProviderRuntimeError as exc:
        raise ProviderProbeError("provider_identity_override_attempt") from exc
    return probe_provider(
        contract,
        api_key=credentials[P6_API_KEY_ENVIRONMENT_KEY],
        transport=transport,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m zscope.benchmarking.provider_runtime")
    commands = parser.add_subparsers(dest="command", required=True)
    probe = commands.add_parser("probe-p6")
    probe.add_argument("--config", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.command != "probe-p6":
            raise ProviderProbeError("internal_failure")
        result = run_p6_provider_probe(args.config.resolve())
    except ProviderProbeError as exc:
        print(
            f"stage=provider; class={exc.failure_class}:1; count=1",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
