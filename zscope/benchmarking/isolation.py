"""Fail-closed execution plans for answer-isolated OCI benchmark scans."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple, cast
from urllib.parse import urlsplit

from zscope.benchmarking.p6_protocol import P6ProtocolError, load_expected_proxy_attestation
from zscope.benchmarking.provider_runtime import ProviderRuntimeContract


ISOLATION_SCHEMA_VERSION = "zscope.benchmark-isolation.v1"
P6_BOOTSTRAP_PROXY_ATTESTATION_SCHEMA_VERSION = "zscope.p6-bootstrap-proxy-attestation.v1"
_PINNED_IMAGE_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]+")
_ALLOWED_RUNTIME_NAMES = frozenset({"podman", "docker"})
_PASSTHROUGH_ENVIRONMENT = frozenset(
    {"Z_SCOPE_API_KEY", "Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL"}
)
TRUTH_ENVIRONMENT_KEYS = frozenset(
    {"Z_SCOPE_BENCHMARK_TRUTH", "Z_SCOPE_GROUND_TRUTH", "GROUND_TRUTH_PATH"}
)
_NETWORK_LABEL_MODE = "io.zscope.network-policy"
_NETWORK_LABEL_SHA = "io.zscope.network-policy-sha256"
_PROXY_LABEL_ROLE = "io.zscope.role"
_PROXY_LABEL_SHA = "io.zscope.network-policy-sha256"
OCI_EXPECTED_PROXY_ATTESTATION_FILE_ENV = "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE"
OCI_EXPECTED_PROXY_ATTESTATION_SHA256_ENV = "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256"
P6_OCI_CLEANUP_SCHEMA_VERSION = "zscope.p6-oci-cleanup.v1"
P6_OCI_CONCURRENCY_GROUP = "p6-pilot-validation"
P6_OCI_LABEL_SCHEMA = "io.zscope.p6-cleanup-contract"
P6_OCI_LABEL_CONCURRENCY_GROUP = "io.zscope.p6-concurrency-group"
P6_OCI_LABEL_REPOSITORY = "io.zscope.p6-repository"
P6_OCI_LABEL_WORKFLOW_RUN_ID = "io.zscope.p6-workflow-run-id"
P6_OCI_LABEL_WORKFLOW_RUN_ATTEMPT = "io.zscope.p6-workflow-run-attempt"
P6_OCI_LABEL_ATTEMPT_ID = "io.zscope.p6-attempt-id"
P6_OCI_LABEL_PHASE = "io.zscope.p6-phase"
_P6_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_P6_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z")
_SECRET_ENVIRONMENT_MARKERS = (
    "API_KEY",
    "ACCESS_KEY",
    "GPG_KEY",
    "AUTHORIZATION",
    "BEARER",
    "CREDENTIAL",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
)
_POSIX_RUNTIME_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_FULL_OCI_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_ENVIRONMENT_KEY_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,127}\Z")
_SAFE_OCI_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
_PROVIDER_SECRET_FD = 3
_PROVIDER_SECRET_WRAPPER = """\
import os
import sys

with open("/proc/self/fd/3", "rb", buffering=0) as stream:
    stream.seek(0)
    payload = stream.read(65537)
os.close(3)
if not payload or len(payload) > 65536 or b"\\x00" in payload or b"\\n" in payload:
    raise SystemExit(126)
os.environ["Z_SCOPE_API_KEY"] = payload.decode("utf-8")
separator = sys.argv.index("--")
command = sys.argv[separator + 1 :]
if not command:
    raise SystemExit(126)
os.execvp(command[0], command)
"""
_PRESERVE_FD_CANARY_WRAPPER = """\
import hashlib
import os
import sys

with open("/proc/self/fd/3", "rb", buffering=0) as stream:
    stream.seek(0)
    payload = stream.read(65)
os.close(3)
if len(payload) != 32 or hashlib.sha256(payload).hexdigest() != sys.argv[1]:
    raise SystemExit(126)
"""
_PODMAN_V4_DEFAULT_CAPABILITIES = frozenset(
    {
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT",
    }
)


class BenchmarkIsolationError(RuntimeError):
    """Raised when a requested isolation claim cannot be established."""


class _OciPhaseInterrupted(KeyboardInterrupt):
    """Internal fixed-shape interrupt used to force OCI cleanup."""


def _safe_phase_name(value: str) -> str:
    return _SAFE_NAME_RE.sub("-", str(value)).strip("-.")[:32] or "phase"


@dataclass(frozen=True)
class P6OciCleanupScope:
    """Exact runner-owned labels used to recover hard-killed P6 scanners."""

    repository: str
    workflow_run_id: str
    workflow_run_attempt: str
    attempt_id: str
    concurrency_group: str = P6_OCI_CONCURRENCY_GROUP

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str],
        *,
        process_environment: Optional[Mapping[str, str]] = None,
    ) -> Optional["P6OciCleanupScope"]:
        process = process_environment if process_environment is not None else os.environ

        def value(name: str) -> str:
            return str(environment.get(name) or process.get(name) or "").strip()

        attempt_id = value("P6_ATTEMPT_ID")
        if not attempt_id:
            return None
        repository = value("GITHUB_REPOSITORY")
        run_id = value("GITHUB_RUN_ID")
        run_attempt = value("GITHUB_RUN_ATTEMPT")
        if (
            _P6_REPOSITORY_RE.fullmatch(repository) is None
            or _P6_POSITIVE_INTEGER_RE.fullmatch(run_id) is None
            or _P6_POSITIVE_INTEGER_RE.fullmatch(run_attempt) is None
            or attempt_id != f"p6-{run_id}-{run_attempt}"
        ):
            raise BenchmarkIsolationError("P6 OCI cleanup scope is invalid")
        return cls(
            repository=repository,
            workflow_run_id=run_id,
            workflow_run_attempt=run_attempt,
            attempt_id=attempt_id,
        )

    def labels(self, phase: str) -> Dict[str, str]:
        return {
            P6_OCI_LABEL_SCHEMA: P6_OCI_CLEANUP_SCHEMA_VERSION,
            P6_OCI_LABEL_CONCURRENCY_GROUP: self.concurrency_group,
            P6_OCI_LABEL_REPOSITORY: self.repository,
            P6_OCI_LABEL_WORKFLOW_RUN_ID: self.workflow_run_id,
            P6_OCI_LABEL_WORKFLOW_RUN_ATTEMPT: self.workflow_run_attempt,
            P6_OCI_LABEL_ATTEMPT_ID: self.attempt_id,
            P6_OCI_LABEL_PHASE: _safe_phase_name(phase),
        }


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _load_bound_expected_proxy_attestation(
    path: str,
    file_sha256: str,
) -> Dict[str, Any]:
    try:
        return dict(load_expected_proxy_attestation(Path(path), expected_file_sha256=file_sha256))
    except (P6ProtocolError, OSError, ValueError):
        raise BenchmarkIsolationError("expected proxy attestation is invalid") from None


_P6_BOOTSTRAP_PROXY_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "repository",
        "image_provenance_sha256",
        "image_provenance_content_sha256",
        "proxy_provision_sha256",
        "proxy_provision_content_sha256",
        "image_ref",
        "image_id",
        "provider_identity_sha256",
        "network_name",
        "egress_network_name",
        "network_names",
        "network_aliases_sha256",
        "proxy_container",
        "proxy_container_id",
        "endpoint_origin",
        "endpoint_host",
        "network_policy_sha256",
        "relay_sha256",
        "relay_projection_sha256",
        "upstreams_sha256",
        "upstream_count",
        "command_projection_sha256",
        "expected_environment_sha256",
        "credential_environment_keys",
        "security_projection_sha256",
        "log_driver_projection_sha256",
        "image_inspect_projection_sha256",
        "proxy_inspect_projection_sha256",
        "bootstrap_preflight_only",
        "formal_evidence",
        "release_eligible",
        "content_sha256",
    }
)


def _validate_bootstrap_proxy_attestation(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the in-memory, pre-toolchain proxy expectation.

    This deliberately is not a substitute for the final cross-job attestation:
    it is accepted only by an explicitly bootstrap-scoped executor and carries
    non-release markers.  Exact fields and a canonical content hash make the
    boundary immutable after it has been derived from the two verified local
    provisioning receipts.
    """

    candidate = dict(value)
    if set(candidate) != _P6_BOOTSTRAP_PROXY_ATTESTATION_FIELDS:
        raise BenchmarkIsolationError("bootstrap proxy attestation fields are invalid")
    run_id = candidate.get("workflow_run_id")
    run_attempt = candidate.get("workflow_run_attempt")
    attempt_id = candidate.get("attempt_id")
    repository = candidate.get("repository")
    if (
        candidate.get("schema_version") != P6_BOOTSTRAP_PROXY_ATTESTATION_SCHEMA_VERSION
        or not isinstance(run_id, str)
        or _P6_POSITIVE_INTEGER_RE.fullmatch(run_id) is None
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt < 1
        or attempt_id != f"p6-{run_id}-{run_attempt}"
        or not isinstance(repository, str)
        or _P6_REPOSITORY_RE.fullmatch(repository) is None
        or candidate.get("bootstrap_preflight_only") is not True
        or candidate.get("formal_evidence") is not False
        or candidate.get("release_eligible") is not False
        or candidate.get("credential_environment_keys") != []
    ):
        raise BenchmarkIsolationError("bootstrap proxy attestation identity is invalid")
    for field in (
        "image_provenance_sha256",
        "image_provenance_content_sha256",
        "proxy_provision_sha256",
        "proxy_provision_content_sha256",
        "provider_identity_sha256",
        "network_aliases_sha256",
        "network_policy_sha256",
        "relay_sha256",
        "relay_projection_sha256",
        "upstreams_sha256",
        "command_projection_sha256",
        "expected_environment_sha256",
        "security_projection_sha256",
        "log_driver_projection_sha256",
        "image_inspect_projection_sha256",
        "proxy_inspect_projection_sha256",
    ):
        if _SHA256_RE.fullmatch(str(candidate.get(field) or "")) is None:
            raise BenchmarkIsolationError("bootstrap proxy attestation digest is invalid")
    if (
        _PINNED_IMAGE_RE.fullmatch(str(candidate.get("image_ref") or "")) is None
        or re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", str(candidate.get("image_id") or "")) is None
        or _FULL_OCI_ID_RE.fullmatch(str(candidate.get("proxy_container_id") or "")) is None
    ):
        raise BenchmarkIsolationError("bootstrap proxy attestation OCI identity is invalid")
    for field in ("network_name", "egress_network_name", "proxy_container"):
        if _SAFE_OCI_NAME_RE.fullmatch(str(candidate.get(field) or "")) is None:
            raise BenchmarkIsolationError("bootstrap proxy attestation OCI name is invalid")
    if candidate.get("network_name") == candidate.get("egress_network_name") or candidate.get(
        "network_names"
    ) != sorted([str(candidate.get("network_name")), str(candidate.get("egress_network_name"))]):
        raise BenchmarkIsolationError("bootstrap proxy attestation network set is invalid")
    origin = str(candidate.get("endpoint_origin") or "")
    parsed = urlsplit(origin)
    upstream_count = candidate.get("upstream_count")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or candidate.get("endpoint_host") != parsed.hostname
        or isinstance(upstream_count, bool)
        or not isinstance(upstream_count, int)
        or upstream_count < 1
    ):
        raise BenchmarkIsolationError("bootstrap proxy attestation endpoint is invalid")
    supplied = str(candidate.get("content_sha256") or "")
    unsigned = dict(candidate)
    unsigned.pop("content_sha256", None)
    if _SHA256_RE.fullmatch(supplied) is None or supplied != _canonical_sha256(unsigned):
        raise BenchmarkIsolationError("bootstrap proxy attestation content hash is invalid")
    return cast(Dict[str, Any], json.loads(json.dumps(candidate)))


def _read_lstat_bound_regular_file(
    path: Path,
    metadata: os.stat_result,
    *,
    context: str,
    limit: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BenchmarkIsolationError(f"{context} is unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != metadata.st_dev
            or before.st_ino != metadata.st_ino
            or before.st_size != metadata.st_size
            or before.st_mtime_ns != metadata.st_mtime_ns
            or before.st_size > limit
        ):
            raise BenchmarkIsolationError(f"{context} identity changed before reading")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if (
        remaining
        or len(payload) != before.st_size
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise BenchmarkIsolationError(f"{context} changed while reading")
    return payload


def _ensure_link_free_directory(path: Path) -> Path:
    candidate = Path(path).absolute()
    try:
        candidate.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BenchmarkIsolationError("OCI evidence directory is unavailable") from exc
    current = candidate
    while current != current.parent:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BenchmarkIsolationError("OCI evidence directory is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BenchmarkIsolationError("OCI evidence directory contains a symbolic link")
        current = current.parent
    return candidate


def _write_oci_phase_log(path: Path, value: Mapping[str, Any]) -> None:
    target = Path(path).absolute()
    parent = _ensure_link_free_directory(target.parent)
    if target.name in {"", ".", ".."}:
        raise BenchmarkIsolationError("OCI phase log target is unsafe")
    payload = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    temporary_name = f".{target.name}.{uuid.uuid4().hex}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: Optional[int] = None
    parent_descriptor: Optional[int] = None
    temporary_path = parent / temporary_name
    try:
        if os.name == "posix":
            parent_before = parent.lstat()
            parent_descriptor = os.open(
                parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            parent_opened = os.fstat(parent_descriptor)
            if not stat.S_ISDIR(parent_opened.st_mode) or (
                parent_opened.st_dev,
                parent_opened.st_ino,
            ) != (parent_before.st_dev, parent_before.st_ino):
                raise BenchmarkIsolationError("OCI phase log directory identity changed")
            try:
                existing = os.stat(
                    target.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                existing = None
            descriptor = os.open(
                temporary_name,
                flags,
                stat.S_IRUSR | stat.S_IWUSR,
                dir_fd=parent_descriptor,
            )
        else:
            try:
                existing = target.lstat()
            except FileNotFoundError:
                existing = None
            descriptor = os.open(temporary_path, flags, stat.S_IRUSR | stat.S_IWUSR)
        if existing is not None and (
            stat.S_ISLNK(existing.st_mode)
            or not stat.S_ISREG(existing.st_mode)
            or existing.st_nlink != 1
        ):
            raise BenchmarkIsolationError("OCI phase log target is unsafe")
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count < 1:
                raise OSError("short OCI phase log write")
            written += count
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BenchmarkIsolationError("OCI phase log temporary file is unsafe")
        os.close(descriptor)
        descriptor = None
        if parent_descriptor is not None:
            os.replace(
                temporary_name,
                target.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            installed = os.stat(
                target.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        else:
            os.replace(temporary_path, target)
            installed = target.lstat()
        if (
            not stat.S_ISREG(installed.st_mode)
            or installed.st_dev != metadata.st_dev
            or installed.st_ino != metadata.st_ino
            or installed.st_nlink != 1
        ):
            raise BenchmarkIsolationError("OCI phase log installation is invalid")
        if parent_descriptor is not None:
            parent_after = parent.lstat()
            if (parent_after.st_dev, parent_after.st_ino) != (
                parent_opened.st_dev,
                parent_opened.st_ino,
            ):
                raise BenchmarkIsolationError("OCI phase log directory identity changed")
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if parent_descriptor is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        else:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        raise
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def sealed_runtime_source_sha256(root: Path) -> str:
    """Hash an all-file, link-free runtime source tree for OCI mounting."""

    base = Path(root).resolve()
    if not base.is_dir():
        raise BenchmarkIsolationError("sealed runtime source does not exist")
    rows: list[Dict[str, Any]] = []
    total_size = 0
    for path in sorted(base.rglob("*"), key=lambda item: item.relative_to(base).as_posix()):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise BenchmarkIsolationError("sealed runtime source is unreadable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise BenchmarkIsolationError("sealed runtime source contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise BenchmarkIsolationError("sealed runtime source contains a special file")
        relative = path.relative_to(base).as_posix()
        if (
            "__pycache__" in path.parts
            or path.suffix.lower() in {".pyc", ".pyo"}
            or any(
                token in relative.lower()
                for token in ("ground_truth", "ground-truth", "/scorer", "/expected")
            )
        ):
            raise BenchmarkIsolationError("sealed runtime source contains a forbidden file")
        payload = _read_lstat_bound_regular_file(
            path,
            metadata,
            context="sealed runtime source",
            limit=64 * 1024 * 1024 - total_size,
        )
        total_size += len(payload)
        if total_size > 64 * 1024 * 1024:
            raise BenchmarkIsolationError("sealed runtime source exceeds the size limit")
        rows.append(
            {
                "path": relative,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if not rows or not any(row["path"] == "__init__.py" for row in rows):
        raise BenchmarkIsolationError("sealed runtime source is incomplete")
    return _canonical_sha256(
        {
            "schema_version": "zscope.sealed-runtime-source.v1",
            "files": rows,
            "file_count": len(rows),
            "total_size": total_size,
        }
    )


def _runtime_family(runtime: str, runtime_path: str = "") -> str:
    raw = Path(runtime_path or runtime).name.lower()
    if raw.endswith(".exe"):
        raw = raw[:-4]
    return raw if raw in _ALLOWED_RUNTIME_NAMES else ""


def _json_object(raw: str, *, context: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BenchmarkIsolationError(f"{context} did not return JSON") from exc
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        value = value[0]
    if not isinstance(value, dict):
        raise BenchmarkIsolationError(f"{context} did not return one JSON object")
    return value


def _json_array(raw: str, *, context: str) -> list[Dict[str, Any]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BenchmarkIsolationError(f"{context} did not return JSON") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise BenchmarkIsolationError(f"{context} did not return a JSON object array")
    return [dict(item) for item in value]


def _nested(mapping: Mapping[str, Any], *path: str) -> Any:
    value: Any = mapping
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _is_secret_environment_key(key: str) -> bool:
    upper = str(key or "").upper()
    return bool(
        upper == "Z_SCOPE_P6_API_KEY_FILE"
        or any(marker in upper for marker in _SECRET_ENVIRONMENT_MARKERS)
    )


def _validated_posix_directory(path: Path, *, uid: int, name: str) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise BenchmarkIsolationError(f"derived OCI {name} is not absolute")
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise BenchmarkIsolationError(f"derived OCI {name} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BenchmarkIsolationError(f"derived OCI {name} is not a regular directory")
    if metadata.st_uid != uid:
        raise BenchmarkIsolationError(f"derived OCI {name} has an unexpected owner")
    return str(candidate.resolve())


def oci_runtime_environment() -> Dict[str, str]:
    """Derive a credential-free OCI CLI environment from the OS identity.

    No caller-controlled ``PATH``, ``HOME``, XDG, loader, Python, proxy, or
    registry variable is accepted.  A rootless POSIX runtime needs its account
    home and per-user runtime directory; those values are independently
    derived from the kernel uid and passwd database and ownership checked.
    Unit-test fakes on non-POSIX hosts receive only a deterministic path and
    locale.  A real formal executor is Linux/WSL-only.
    """

    result = {
        "PATH": _POSIX_RUNTIME_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if os.name != "posix":
        return result
    try:
        getuid = getattr(os, "getuid", None)
        getpwuid = getattr(importlib.import_module("pwd"), "getpwuid", None)
        if not callable(getuid) or not callable(getpwuid):
            raise OSError("POSIX account APIs are unavailable")
        uid = int(getuid())
        account = getpwuid(uid)
    except (ImportError, KeyError, OSError) as exc:
        raise BenchmarkIsolationError("rootless OCI account identity is unavailable") from exc
    home = _validated_posix_directory(Path(account.pw_dir), uid=uid, name="home")
    result.update({"HOME": home, "USER": account.pw_name, "LOGNAME": account.pw_name})
    runtime_dir = Path("/run/user") / str(uid)
    if runtime_dir.exists() or runtime_dir.is_symlink():
        result["XDG_RUNTIME_DIR"] = _validated_posix_directory(
            runtime_dir, uid=uid, name="runtime directory"
        )
    return result


def _environment_entries(value: Any) -> tuple[Dict[str, str], bool]:
    """Parse OCI ``Config.Env`` without ever returning unkeyed raw values."""

    if value is None:
        return {}, True
    if not isinstance(value, list):
        return {}, False
    entries: Dict[str, str] = {}
    for raw in value:
        if not isinstance(raw, str) or "=" not in raw:
            return {}, False
        key, item = raw.split("=", 1)
        if not key or key in entries:
            return {}, False
        entries[key] = item
    return entries, True


def _credential_metadata_safe(value: Any) -> bool:
    entries, parsed = _environment_entries(value)
    return parsed and not any(_is_secret_environment_key(key) for key in entries)


def _inspect_projection_sha256(inspect: Mapping[str, Any]) -> str:
    """Hash inspect evidence after replacing environment values with key names."""

    projection = json.loads(json.dumps(dict(inspect), ensure_ascii=False))
    config = projection.get("Config")
    if isinstance(config, dict) and "Env" in config:
        entries, parsed = _environment_entries(config.get("Env"))
        config["Env"] = sorted(entries) if parsed else ["<invalid-environment-metadata>"]
    return _canonical_sha256(projection)


def _normalized_capabilities(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise BenchmarkIsolationError("model endpoint proxy capabilities are invalid")
    normalized = [item.upper().removeprefix("CAP_") for item in value]
    if len(normalized) != len(set(normalized)):
        raise BenchmarkIsolationError("model endpoint proxy capabilities are invalid")
    return sorted(normalized)


def _normalized_tmpfs_options(value: Any) -> list[str]:
    if not isinstance(value, str):
        raise BenchmarkIsolationError("model endpoint proxy tmpfs is invalid")
    rows = [item.strip().lower() for item in value.split(",")]
    if not rows or any(not item for item in rows) or len(rows) != len(set(rows)):
        raise BenchmarkIsolationError("model endpoint proxy tmpfs is invalid")
    return sorted(rows)


def _regular_file_identity(path: Path) -> tuple[str, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BenchmarkIsolationError("model endpoint proxy relay is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BenchmarkIsolationError("model endpoint proxy relay is invalid")
    content = _read_lstat_bound_regular_file(
        path,
        metadata,
        context="model endpoint proxy relay",
        limit=1024 * 1024,
    )
    sha256 = hashlib.sha256(content).hexdigest()
    projection = _canonical_sha256(
        {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "sha256": sha256,
            "size": metadata.st_size,
            "uid": metadata.st_uid,
        }
    )
    return sha256, projection


def _is_rootless_info(runtime_family: str, info: Mapping[str, Any]) -> bool:
    if runtime_family == "podman":
        return any(
            value is True
            for value in (
                _nested(info, "host", "security", "rootless"),
                _nested(info, "host", "rootless"),
                info.get("rootless"),
            )
        )
    options = info.get("SecurityOptions") or info.get("securityOptions") or []
    if isinstance(options, str):
        options = [options]
    return isinstance(options, list) and any("rootless" in str(value).lower() for value in options)


@dataclass(frozen=True)
class OciNetworkPolicy:
    network_name: str
    proxy_container: str
    endpoint_origin: str
    endpoint_host: str
    policy_sha256: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> "OciNetworkPolicy":
        """Compatibility constructor for non-bundled benchmark callers."""

        return cls._from_endpoint(
            environment,
            endpoint=str(environment.get("Z_SCOPE_LLM_BASE_URL") or "").strip(),
        )

    @classmethod
    def from_provider_contract(
        cls,
        environment: Mapping[str, str],
        provider_contract: ProviderRuntimeContract,
    ) -> "OciNetworkPolicy":
        return cls._from_endpoint(environment, endpoint=provider_contract.base_url)

    @classmethod
    def _from_endpoint(
        cls,
        environment: Mapping[str, str],
        *,
        endpoint: str,
    ) -> "OciNetworkPolicy":
        network = str(environment.get("Z_SCOPE_BENCHMARK_OCI_NETWORK") or "").strip()
        proxy = str(environment.get("Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER") or "").strip()
        parsed = urlsplit(endpoint)
        if not network:
            raise BenchmarkIsolationError("formal OCI requires an explicit internal network")
        if not proxy:
            raise BenchmarkIsolationError(
                "formal OCI requires an explicit model endpoint proxy container"
            )
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise BenchmarkIsolationError("model endpoint must be an explicit HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BenchmarkIsolationError(
                "model endpoint policy URL cannot contain credentials, query, or fragment"
            )
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        origin = f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"
        contract = {
            "mode": "rootless-internal-model-proxy",
            "network": network,
            "proxy_container": proxy,
            "endpoint_origin": origin,
        }
        return cls(
            network_name=network,
            proxy_container=proxy,
            endpoint_origin=origin,
            endpoint_host=parsed.hostname.lower(),
            policy_sha256=_canonical_sha256(contract),
        )


@dataclass(frozen=True)
class OciIsolationPlan:
    runtime: str
    image: str
    scan_input: str
    artifact_output: str
    cache_output: str
    argv: Tuple[str, ...]
    environment_keys: Tuple[str, ...]
    runtime_source: str = ""
    runtime_source_sha256: str = ""
    network_mode: str = "unverified"
    network_name: str = ""
    network_policy_sha256: str = ""
    schema_version: str = ISOLATION_SCHEMA_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": "oci",
            "runtime": self.runtime,
            "image": self.image,
            "scan_input": self.scan_input,
            "artifact_output": self.artifact_output,
            "cache_output": self.cache_output,
            "scanner_cwd": "/zscope-input",
            "mounts": [
                {
                    "source": self.scan_input,
                    "destination": "/zscope-input",
                    "purpose": "scan_input",
                    "read_only": True,
                },
                {
                    "source": self.cache_output,
                    "destination": "/zscope-cache",
                    "purpose": "cache",
                    "read_only": False,
                },
                {
                    "source": self.artifact_output,
                    "destination": "/zscope-output",
                    "purpose": "artifact_output",
                    "read_only": False,
                },
                *(
                    [
                        {
                            "source": self.runtime_source,
                            "destination": "/zscope-runtime/zscope",
                            "purpose": "runtime_source",
                            "read_only": True,
                        }
                    ]
                    if self.runtime_source
                    else []
                ),
            ],
            "argv": list(self.argv),
            "environment_keys": list(self.environment_keys),
            "network_mode": self.network_mode,
            "network_name": self.network_name,
            "network_policy_sha256": self.network_policy_sha256,
            "truth_mounted": False,
            "repository_mounted": False,
            "runtime_source_mounted": bool(self.runtime_source),
            "runtime_source_sha256": self.runtime_source_sha256,
            "plan_validated": True,
            "execution_verified": False,
            "network_restriction_verified": False,
            "scanner_cwd_isolated": False,
            "mounts_verified": False,
            "release_capable": False,
        }


def oci_capability(
    *,
    runtime: str = "",
    image: str = "",
    which: Optional[Callable[[str], Optional[str]]] = None,
) -> Dict[str, Any]:
    selected = str(runtime or "").strip()
    locator = which or shutil.which
    executable = locator(selected) if selected else None
    errors = []
    if not selected:
        errors.append("OCI runtime was not explicitly selected")
    elif executable is None:
        errors.append(f"OCI runtime is unavailable: {selected}")
    elif not _runtime_family(selected, executable):
        errors.append("OCI runtime must be explicitly podman or docker")
    if not _PINNED_IMAGE_RE.fullmatch(str(image or "")):
        errors.append("OCI image must be pinned by a 64-hex sha256 digest")
    return {
        "schema_version": ISOLATION_SCHEMA_VERSION,
        "mode": "oci",
        "runtime": selected,
        "runtime_path": executable or "",
        "image": str(image or ""),
        "available": not errors,
        "rootless_verified": False,
        "image_digest_verified": False,
        "execution_verified": False,
        "release_capable": False,
        "errors": errors,
    }


def build_oci_isolation_plan(
    *,
    runtime: str,
    image: str,
    scan_input: Path,
    artifact_output: Path,
    cache_output: Optional[Path] = None,
    scan_command: Sequence[str],
    environment: Mapping[str, str],
    provider_contract: Optional[ProviderRuntimeContract] = None,
    runtime_source: Optional[Path] = None,
) -> OciIsolationPlan:
    capability = oci_capability(runtime=runtime, image=image)
    if not capability["available"]:
        raise BenchmarkIsolationError("; ".join(capability["errors"]))
    source = Path(scan_input).resolve()
    output = Path(artifact_output).resolve()
    cache = Path(cache_output or (output.parent / "oci-cache")).resolve()
    if not source.is_dir():
        raise BenchmarkIsolationError(f"scan input does not exist: {source}")
    if not output.is_dir():
        raise BenchmarkIsolationError(f"artifact output does not exist: {output}")
    if cache_output is None:
        cache.mkdir(parents=True, exist_ok=True)
    if not cache.is_dir():
        raise BenchmarkIsolationError(f"cache output does not exist: {cache}")
    runtime_tree = Path(runtime_source).resolve() if runtime_source is not None else None
    runtime_tree_sha256 = (
        sealed_runtime_source_sha256(runtime_tree) if runtime_tree is not None else ""
    )
    roots = tuple(path for path in (source, output, cache, runtime_tree) if path is not None)
    if any(
        left == right or left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(roots)
        for right in roots[index + 1 :]
    ):
        raise BenchmarkIsolationError(
            "sealed input, artifact output, and cache must be disjoint directories"
        )
    forbidden = [
        path
        for path in source.rglob("*")
        if path.name.lower() in {"ground_truth.json", "ground_truth.md"}
    ]
    if forbidden:
        raise BenchmarkIsolationError("truth material is present in the scan input")
    command_text = json.dumps([str(value) for value in scan_command]).lower()
    if "ground_truth" in command_text or "benchmark/" in command_text:
        raise BenchmarkIsolationError("scan command references benchmark answer material")
    if provider_contract is not None:
        missing = [
            key
            for key in provider_contract.required_environment_keys
            if not str(environment.get(key) or "").strip()
        ]
        if missing:
            raise BenchmarkIsolationError(
                "provider contract environment is incomplete: " + ", ".join(missing)
            )
    allowed_keys = (
        frozenset(provider_contract.required_environment_keys)
        if provider_contract is not None
        else _PASSTHROUGH_ENVIRONMENT
    )
    allowed_environment = tuple(sorted(key for key in environment if key in allowed_keys))
    policy: Optional[OciNetworkPolicy]
    try:
        policy = (
            OciNetworkPolicy.from_provider_contract(environment, provider_contract)
            if provider_contract is not None
            else OciNetworkPolicy.from_environment(environment)
        )
    except BenchmarkIsolationError:
        policy = None
    argv = (
        str(capability["runtime_path"]),
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--workdir",
        "/zscope-input",
        "--mount",
        f"type=bind,src={source},dst=/zscope-input,readonly",
        "--mount",
        f"type=bind,src={output},dst=/zscope-output",
        "--mount",
        f"type=bind,src={cache},dst=/zscope-cache",
        *(
            ("--mount", f"type=bind,src={runtime_tree},dst=/zscope-runtime/zscope,readonly")
            if runtime_tree is not None
            else ()
        ),
        *(("--network", policy.network_name) if policy is not None else ()),
        image,
        *tuple(str(value) for value in scan_command),
    )
    return OciIsolationPlan(
        runtime=runtime,
        image=image,
        scan_input=str(source),
        artifact_output=str(output),
        cache_output=str(cache),
        argv=argv,
        environment_keys=allowed_environment,
        runtime_source=str(runtime_tree) if runtime_tree is not None else "",
        runtime_source_sha256=runtime_tree_sha256,
        network_mode=("model-endpoint-only" if policy is not None else "unverified"),
        network_name=(policy.network_name if policy is not None else ""),
        network_policy_sha256=(policy.policy_sha256 if policy is not None else ""),
    )


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]
SecretFdFactory = Callable[[str], int]


@dataclass(frozen=True)
class _ProviderFdHandoff:
    descriptor: int
    restore_from: Optional[int] = None
    restore_inheritable: bool = False


@dataclass(frozen=True)
class _DirectoryBinding:
    purpose: str
    path: Path
    descriptor: Optional[int]
    device: int
    inode: int
    content_sha256: str = ""

    @property
    def mount_source(self) -> str:
        if self.descriptor is None:
            return str(self.path)
        return f"/proc/self/fd/{self.descriptor}"


def _directory_identity(path: Path, *, context: str) -> tuple[int, int]:
    try:
        metadata = Path(path).lstat()
    except OSError as exc:
        raise BenchmarkIsolationError(f"{context} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BenchmarkIsolationError(f"{context} is not a link-free directory")
    return int(metadata.st_dev), int(metadata.st_ino)


def _directory_content_sha256(path: Path, *, context: str) -> str:
    root = Path(path)
    rows: list[Dict[str, Any]] = []
    total_size = 0
    try:
        children = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    except OSError as exc:
        raise BenchmarkIsolationError(f"{context} is unreadable") from exc
    for child in children:
        try:
            metadata = child.lstat()
        except OSError as exc:
            raise BenchmarkIsolationError(f"{context} is unreadable") from exc
        relative = child.relative_to(root).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            raise BenchmarkIsolationError(f"{context} contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            rows.append({"path": relative + "/", "type": "directory"})
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise BenchmarkIsolationError(f"{context} contains a special file")
        if any(
            token in relative.lower()
            for token in (
                "ground_truth",
                "ground-truth",
                "benchmark_truth",
            )
        ):
            raise BenchmarkIsolationError(f"{context} contains forbidden answer material")
        payload = _read_lstat_bound_regular_file(
            child,
            metadata,
            context=context,
            limit=1024 * 1024 * 1024 - total_size,
        )
        total_size += len(payload)
        if total_size > 1024 * 1024 * 1024:
            raise BenchmarkIsolationError(f"{context} exceeds the size limit")
        rows.append(
            {
                "path": relative,
                "type": "file",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return _canonical_sha256(
        {
            "schema_version": "zscope.oci-directory-content.v1",
            "rows": rows,
            "total_size": total_size,
        }
    )


def _provider_secret_memfd(name: str) -> int:
    create = getattr(os, "memfd_create", None)
    if os.name != "posix" or not callable(create):
        raise BenchmarkIsolationError("anonymous provider credential handoff is unavailable")
    flags = int(getattr(os, "MFD_CLOEXEC", 0)) | int(getattr(os, "MFD_ALLOW_SEALING", 0))
    try:
        return int(create(name, flags=flags))
    except OSError as exc:
        raise BenchmarkIsolationError("anonymous provider credential handoff failed") from exc


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for nested_value in value.values():
            yield from _strings(nested_value)
    elif isinstance(value, (list, tuple)):
        for nested_value in value:
            yield from _strings(nested_value)


def _labels(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _container_networks(inspect: Mapping[str, Any]) -> Mapping[str, Any]:
    networks = _nested(inspect, "NetworkSettings", "Networks")
    return networks if isinstance(networks, Mapping) else {}


def _network_peers(inspect: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    raw = inspect.get("Containers") or inspect.get("containers") or {}
    if isinstance(raw, Mapping):
        return {
            str(key): dict(value) if isinstance(value, Mapping) else {}
            for key, value in raw.items()
        }
    if isinstance(raw, list):
        result: Dict[str, Dict[str, Any]] = {}
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            identity = str(item.get("Id") or item.get("ID") or item.get("id") or "")
            if identity:
                result[identity] = dict(item)
        return result
    return {}


def _identity_matches(left: str, right: str) -> bool:
    left = str(left or "").lower()
    right = str(right or "").lower()
    return bool(left and right and left == right)


def _image_identity_matches(left: str, right: str) -> bool:
    def normalized(value: str) -> str:
        raw = str(value or "").lower()
        if "@sha256:" in raw:
            return raw.rsplit("@sha256:", 1)[1]
        if raw.startswith("sha256:"):
            return raw[len("sha256:") :]
        return raw

    return _identity_matches(normalized(left), normalized(right))


@dataclass(frozen=True)
class OciPhaseResult:
    phase: str
    seconds: float
    return_code: int
    evidence: Dict[str, Any]


class RootlessOciExecutor:
    """Run formal scan phases and derive claims only from runtime inspection.

    The scanner gets a sealed read-only input tree.  All mutable project state,
    including build products and Z-SCOPE caches/reports, lives below the
    dedicated ``/zscope-cache`` mount.  ``/zscope-output`` is reserved for
    configs and exported artifacts.  Network egress is provided by one
    pre-provisioned model proxy on a rootless *internal* OCI network.
    """

    def __init__(
        self,
        *,
        runtime: str,
        image: str,
        scan_input: Path,
        artifact_output: Path,
        cache_output: Path,
        environment: Mapping[str, str],
        provider_contract: Optional[ProviderRuntimeContract] = None,
        runtime_source: Optional[Path] = None,
        process_runner: ProcessRunner = subprocess.run,
        which: Optional[Callable[[str], Optional[str]]] = None,
        secret_fd_factory: SecretFdFactory = _provider_secret_memfd,
        bootstrap_expected_proxy_attestation: Optional[Mapping[str, Any]] = None,
    ) -> None:
        capability = oci_capability(runtime=runtime, image=image, which=which)
        if not capability["available"]:
            raise BenchmarkIsolationError("; ".join(capability["errors"]))
        self.runtime = str(runtime)
        self.runtime_path = str(capability["runtime_path"])
        self.runtime_family = _runtime_family(runtime, self.runtime_path)
        self.image = str(image)
        self.scan_input = Path(scan_input).resolve()
        self.artifact_output = Path(artifact_output).resolve()
        self.cache_output = Path(cache_output).resolve()
        self.runtime_source = Path(runtime_source).resolve() if runtime_source is not None else None
        self.runtime_source_sha256 = (
            sealed_runtime_source_sha256(self.runtime_source)
            if self.runtime_source is not None
            else ""
        )
        source_environment = {
            str(key): str(value)
            for key, value in environment.items()
            if key not in TRUTH_ENVIRONMENT_KEYS
            and "GROUND_TRUTH" not in str(key).upper()
            and "BENCHMARK_TRUTH" not in str(key).upper()
        }
        self.provider_contract = provider_contract
        if provider_contract is not None:
            missing = [
                key
                for key in provider_contract.required_environment_keys
                if not str(source_environment.get(key) or "").strip()
            ]
            if missing:
                raise BenchmarkIsolationError(
                    "provider contract environment is incomplete: " + ", ".join(missing)
                )
        if provider_contract is not None:
            self.provider_identity_sha256 = provider_contract.identity_sha256
        else:
            base_url = str(source_environment.get("Z_SCOPE_LLM_BASE_URL") or "").strip()
            model = str(source_environment.get("Z_SCOPE_LLM_MODEL") or "").strip()
            self.provider_identity_sha256 = (
                _canonical_sha256(
                    {
                        "schema_version": "zscope.oci-provider-identity.v1",
                        "base_url": base_url.rstrip("/"),
                        "model": model,
                    }
                )
                if base_url and model
                else ""
            )
        self.container_environment_keys = tuple(
            sorted(
                key
                for key in source_environment
                if key
                in (
                    frozenset(provider_contract.required_environment_keys)
                    if provider_contract is not None
                    else _PASSTHROUGH_ENVIRONMENT
                )
            )
        )
        self.credential_environment_keys = tuple(
            key
            for key in self.container_environment_keys
            if key == "Z_SCOPE_API_KEY" or _is_secret_environment_key(key)
        )
        # Freeze only the environment keys named by the provider contract.
        # They are withheld from every metadata/preflight/inspect/cleanup
        # subprocess and supplied solely to the matching OCI ``run`` command.
        self._provider_environment = {
            key: source_environment[key]
            for key in self.container_environment_keys
            if key in source_environment
        }
        # Freeze a minimal runtime process context independently of caller and
        # ambient environment values.
        self.environment = oci_runtime_environment()
        self.p6_cleanup_scope = P6OciCleanupScope.from_environment(source_environment)
        self.network_policy = (
            OciNetworkPolicy.from_provider_contract(source_environment, provider_contract)
            if provider_contract is not None
            else OciNetworkPolicy.from_environment(source_environment)
        )
        attestation_path = str(
            source_environment.get(OCI_EXPECTED_PROXY_ATTESTATION_FILE_ENV) or ""
        ).strip()
        attestation_file_sha256 = str(
            source_environment.get(OCI_EXPECTED_PROXY_ATTESTATION_SHA256_ENV) or ""
        ).strip()
        if bool(attestation_path) != bool(attestation_file_sha256):
            raise BenchmarkIsolationError("expected proxy attestation inputs are incomplete")
        if attestation_path and bootstrap_expected_proxy_attestation is not None:
            raise BenchmarkIsolationError(
                "final and bootstrap expected proxy attestations are mutually exclusive"
            )
        if not attestation_path and bootstrap_expected_proxy_attestation is None:
            raise BenchmarkIsolationError("expected proxy attestation is required")
        if attestation_path and not Path(attestation_path).is_absolute():
            raise BenchmarkIsolationError("expected proxy attestation path must be absolute")
        self._bootstrap_preflight_only = bootstrap_expected_proxy_attestation is not None
        self.expected_proxy_attestation = (
            _validate_bootstrap_proxy_attestation(bootstrap_expected_proxy_attestation)
            if bootstrap_expected_proxy_attestation is not None
            else _load_bound_expected_proxy_attestation(attestation_path, attestation_file_sha256)
        )
        self.expected_proxy_attestation_path = Path(attestation_path) if attestation_path else None
        self.expected_proxy_attestation_file_sha256 = attestation_file_sha256
        if self.expected_proxy_attestation:
            expected = self.expected_proxy_attestation
            if (
                expected.get("image_ref") != self.image
                or expected.get("proxy_container") != self.network_policy.proxy_container
                or expected.get("network_name") != self.network_policy.network_name
                or expected.get("provider_identity_sha256") != self.provider_identity_sha256
                or expected.get("network_policy_sha256") != self.network_policy.policy_sha256
                or expected.get("endpoint_origin") != self.network_policy.endpoint_origin
                or expected.get("endpoint_host") != self.network_policy.endpoint_host
            ):
                raise BenchmarkIsolationError("expected proxy attestation binding is invalid")
            if self.p6_cleanup_scope is not None and (
                expected.get("workflow_run_id") != self.p6_cleanup_scope.workflow_run_id
                or expected.get("workflow_run_attempt")
                != int(self.p6_cleanup_scope.workflow_run_attempt)
                or expected.get("attempt_id") != self.p6_cleanup_scope.attempt_id
            ):
                raise BenchmarkIsolationError("expected proxy attestation run binding is invalid")
            if self._bootstrap_preflight_only and (
                self.p6_cleanup_scope is None
                or expected.get("repository") != self.p6_cleanup_scope.repository
                or expected.get("workflow_run_id") != self.p6_cleanup_scope.workflow_run_id
                or expected.get("workflow_run_attempt")
                != int(self.p6_cleanup_scope.workflow_run_attempt)
                or expected.get("attempt_id") != self.p6_cleanup_scope.attempt_id
            ):
                raise BenchmarkIsolationError("bootstrap proxy attestation run binding is invalid")
        self._run = process_runner
        self._secret_fd_factory = secret_fd_factory
        self._preflight: Optional[Dict[str, Any]] = None
        self._phases: list[Dict[str, Any]] = []
        # Official base images may carry public build metadata whose key names
        # look credential-like (for example ``GPG_KEY``).  Scanner containers
        # must not inherit any credential-shaped image environment entry.  The
        # names are learned from immutable image inspection and removed by the
        # rootless runtime before explicitly forwarding the one live provider
        # credential selected by the sealed provider contract.
        self._image_environment_unset_keys: tuple[str, ...] = ()
        self._image_labels: Dict[str, str] = {}
        self._validate_roots()
        self._root_identities = {
            "scan_input": _directory_identity(self.scan_input, context="sealed scan input"),
            "artifact_output": _directory_identity(
                self.artifact_output, context="OCI artifact output"
            ),
            "cache": _directory_identity(self.cache_output, context="OCI cache output"),
            **(
                {
                    "runtime_source": _directory_identity(
                        self.runtime_source, context="sealed runtime source"
                    )
                }
                if self.runtime_source is not None
                else {}
            ),
        }
        self._scan_input_content_sha256 = _directory_content_sha256(
            self.scan_input, context="sealed scan input"
        )
        if self._bootstrap_preflight_only:
            # The bootstrap executor proves only the credential-free toolchain
            # phase.  Drop the placeholder immediately so it cannot reach an
            # OCI subprocess even if a future call site regresses.
            self._clear_provider_credentials()

    def _clear_provider_credentials(self) -> None:
        self._provider_environment.clear()

    def _verify_runtime_source_integrity(self) -> None:
        if self.runtime_source is None:
            return
        if sealed_runtime_source_sha256(self.runtime_source) != self.runtime_source_sha256:
            self._clear_provider_credentials()
            raise BenchmarkIsolationError("sealed runtime source changed after binding")

    def _verify_expected_proxy_attestation_integrity(self) -> None:
        if self.expected_proxy_attestation_path is None:
            return
        current = _load_bound_expected_proxy_attestation(
            str(self.expected_proxy_attestation_path),
            self.expected_proxy_attestation_file_sha256,
        )
        if current != self.expected_proxy_attestation:
            self._clear_provider_credentials()
            raise BenchmarkIsolationError("expected proxy attestation changed after binding")

    def _validate_roots(self) -> None:
        for label, path in (
            ("scan input", self.scan_input),
            ("artifact output", self.artifact_output),
            ("cache output", self.cache_output),
            *(
                (("runtime source", self.runtime_source),)
                if self.runtime_source is not None
                else ()
            ),
        ):
            if not path.is_dir():
                raise BenchmarkIsolationError(f"{label} does not exist: {path}")
        roots = tuple(
            path
            for path in (
                self.scan_input,
                self.artifact_output,
                self.cache_output,
                self.runtime_source,
            )
            if path is not None
        )
        if any(
            left == right or left.is_relative_to(right) or right.is_relative_to(left)
            for index, left in enumerate(roots)
            for right in roots[index + 1 :]
        ):
            raise BenchmarkIsolationError(
                "sealed input, artifact output, and cache must be disjoint directories"
            )
        if any(
            path.name.lower() in {"ground_truth.json", "ground_truth.md"}
            for path in self.scan_input.rglob("*")
        ):
            raise BenchmarkIsolationError("truth material is present in the scan input")

    def _invoke(
        self,
        argv: Sequence[str],
        *,
        pass_fds: Sequence[int] = (),
    ) -> subprocess.CompletedProcess[str]:
        kwargs: Dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "check": False,
            "env": dict(self.environment),
        }
        if pass_fds:
            kwargs["pass_fds"] = tuple(int(value) for value in pass_fds)
        return self._run(
            [str(value) for value in argv],
            **kwargs,
        )

    def _create_cidfile_directory(self) -> Path:
        if os.name == "posix":
            base = Path(self.environment.get("XDG_RUNTIME_DIR") or "/tmp")
            try:
                metadata = base.lstat()
            except OSError as exc:
                raise BenchmarkIsolationError("OCI container ID directory is unavailable") from exc
            getuid = getattr(os, "getuid", None)
            current_uid = int(getuid()) if callable(getuid) else -1
            acceptable_tmp = bool(
                base == Path("/tmp")
                and stat.S_ISDIR(metadata.st_mode)
                and metadata.st_mode & stat.S_ISVTX
            )
            if stat.S_ISLNK(metadata.st_mode) or not (
                stat.S_ISDIR(metadata.st_mode)
                and (acceptable_tmp or metadata.st_uid == current_uid)
            ):
                raise BenchmarkIsolationError("OCI container ID directory is unsafe")
        else:
            base = self.artifact_output.parent
        try:
            directory = Path(tempfile.mkdtemp(prefix="zscope-oci-cids-", dir=str(base))).absolute()
            directory.chmod(stat.S_IRWXU)
            metadata = directory.lstat()
        except OSError as exc:
            raise BenchmarkIsolationError("OCI container ID directory is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (os.name == "posix" and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO))
        ):
            raise BenchmarkIsolationError("OCI container ID directory is unsafe")
        return directory

    @staticmethod
    def _read_container_id(path: Path) -> str:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise BenchmarkIsolationError("OCI runtime did not write a container ID") from exc
        payload = _read_lstat_bound_regular_file(
            path,
            metadata,
            context="OCI container ID file",
            limit=128,
        )
        try:
            identity = payload.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise BenchmarkIsolationError("OCI runtime container ID is invalid") from exc
        if _FULL_OCI_ID_RE.fullmatch(identity) is None:
            raise BenchmarkIsolationError("OCI runtime container ID is invalid")
        return identity

    @staticmethod
    def _remove_cidfile_directory(directory: Optional[Path], cidfile: Optional[Path]) -> bool:
        if directory is None:
            return True
        failed = False
        if cidfile is not None:
            try:
                cidfile.unlink(missing_ok=True)
            except OSError:
                failed = True
        try:
            directory.rmdir()
        except OSError:
            failed = True
        return not failed

    def _open_directory_binding(
        self,
        *,
        purpose: str,
        path: Path,
        content_sha256: str = "",
    ) -> _DirectoryBinding:
        context = f"OCI {purpose} binding"
        expected_device, expected_inode = self._root_identities[purpose]
        current_device, current_inode = _directory_identity(path, context=context)
        if (current_device, current_inode) != (expected_device, expected_inode):
            raise BenchmarkIsolationError(f"{context} identity changed")
        descriptor: Optional[int] = None
        try:
            if os.name == "posix":
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                descriptor = os.open(path, flags)
                if descriptor == _PROVIDER_SECRET_FD:
                    duplicate = os.dup(descriptor)
                    os.close(descriptor)
                    descriptor = duplicate
                os.set_inheritable(descriptor, False)
                opened = os.fstat(descriptor)
                if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                    expected_device,
                    expected_inode,
                ):
                    raise BenchmarkIsolationError(f"{context} identity changed")
                content_root = Path(f"/proc/self/fd/{descriptor}")
            else:
                content_root = path
            if (
                content_sha256
                and _directory_content_sha256(content_root, context=context) != content_sha256
            ):
                raise BenchmarkIsolationError(f"{context} content changed")
            return _DirectoryBinding(
                purpose=purpose,
                path=path,
                descriptor=descriptor,
                device=expected_device,
                inode=expected_inode,
                content_sha256=content_sha256,
            )
        except BaseException:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise

    def _open_phase_directory_bindings(self) -> Dict[str, _DirectoryBinding]:
        opened: Dict[str, _DirectoryBinding] = {}
        rows = (
            ("scan_input", self.scan_input, self._scan_input_content_sha256),
            ("artifact_output", self.artifact_output, ""),
            ("cache", self.cache_output, ""),
            *(
                (("runtime_source", self.runtime_source, ""),)
                if self.runtime_source is not None
                else ()
            ),
        )
        try:
            for purpose, path, content_sha256 in rows:
                assert path is not None
                opened[purpose] = self._open_directory_binding(
                    purpose=purpose,
                    path=path,
                    content_sha256=content_sha256,
                )
        except BaseException:
            self._close_directory_bindings(opened.values())
            raise
        return opened

    @staticmethod
    def _close_directory_bindings(bindings: Iterable[_DirectoryBinding]) -> bool:
        failed = False
        for binding in tuple(bindings):
            if binding.descriptor is None:
                continue
            try:
                os.close(binding.descriptor)
            except OSError:
                failed = True
        return not failed

    def _verify_directory_bindings(self, bindings: Mapping[str, _DirectoryBinding]) -> str:
        projection: list[Dict[str, Any]] = []
        for purpose in sorted(bindings):
            binding = bindings[purpose]
            device, inode = _directory_identity(binding.path, context=f"OCI {purpose} binding")
            if (device, inode) != (binding.device, binding.inode):
                raise BenchmarkIsolationError(f"OCI {purpose} binding identity changed")
            if binding.descriptor is not None:
                opened = os.fstat(binding.descriptor)
                if (opened.st_dev, opened.st_ino) != (binding.device, binding.inode):
                    raise BenchmarkIsolationError(f"OCI {purpose} binding identity changed")
                content_root = Path(f"/proc/self/fd/{binding.descriptor}")
            else:
                content_root = binding.path
            if (
                binding.content_sha256
                and _directory_content_sha256(content_root, context=f"OCI {purpose} binding")
                != binding.content_sha256
            ):
                raise BenchmarkIsolationError(f"OCI {purpose} binding content changed")
            projection.append(
                {
                    "purpose": purpose,
                    "device": binding.device,
                    "inode": binding.inode,
                    "content_sha256": binding.content_sha256,
                    "mount_source_kind": (
                        "stable-directory-fd" if binding.descriptor is not None else "verified-path"
                    ),
                }
            )
        return _canonical_sha256(
            {
                "schema_version": "zscope.oci-directory-bindings.v1",
                "bindings": projection,
            }
        )

    def _create_provider_handoffs(
        self,
        *,
        phase: str,
        credential_keys: Sequence[str],
    ) -> Dict[str, _ProviderFdHandoff]:
        if not credential_keys:
            return {}
        if self.runtime_family != "podman":
            raise BenchmarkIsolationError("provider credential handoff requires rootless Podman")
        if tuple(credential_keys) != ("Z_SCOPE_API_KEY",):
            raise BenchmarkIsolationError("provider credential handoff contract is invalid")
        created: Dict[str, _ProviderFdHandoff] = {}
        for key in credential_keys:
            value = str(self._provider_environment.get(key) or "")
            if not value:
                self._close_provider_handoffs(created.values())
                raise BenchmarkIsolationError("provider credentials are unavailable for OCI phase")
            if _ENVIRONMENT_KEY_RE.fullmatch(key) is None:
                self._close_provider_handoffs(created.values())
                raise BenchmarkIsolationError("provider credential key is invalid")
            try:
                raw = value.encode("utf-8")
                if not raw or len(raw) > 65536 or b"\x00" in raw or b"\n" in raw:
                    raise BenchmarkIsolationError("provider credential value is invalid")
                created[key] = self._create_anonymous_handoff(
                    name=f"zscope-{_safe_phase_name(phase)}-{uuid.uuid4().hex[:16]}",
                    payload=raw,
                )
            except BaseException:
                self._close_provider_handoffs(created.values())
                raise BenchmarkIsolationError(
                    "anonymous provider credential handoff failed"
                ) from None
        return created

    def _create_anonymous_handoff(
        self,
        *,
        name: str,
        payload: bytes,
    ) -> _ProviderFdHandoff:
        descriptor = self._secret_fd_factory(name)
        handoff: Optional[_ProviderFdHandoff] = None
        try:
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count < 1:
                    raise OSError("short anonymous descriptor write")
                written += count
            os.lseek(descriptor, 0, os.SEEK_SET)
            fchmod = getattr(os, "fchmod", None)
            if not callable(fchmod):
                if os.name == "posix":
                    raise BenchmarkIsolationError(
                        "anonymous descriptor permissions are unavailable"
                    )
            else:
                fchmod(descriptor, stat.S_IRUSR)
            if os.name == "posix":
                fcntl = importlib.import_module("fcntl")
                seals = (
                    int(getattr(fcntl, "F_SEAL_SEAL", 0))
                    | int(getattr(fcntl, "F_SEAL_SHRINK", 0))
                    | int(getattr(fcntl, "F_SEAL_GROW", 0))
                    | int(getattr(fcntl, "F_SEAL_WRITE", 0))
                )
                add_seals = getattr(fcntl, "F_ADD_SEALS", None)
                seal_descriptor = getattr(fcntl, "fcntl", None)
                if not seals or add_seals is None or not callable(seal_descriptor):
                    raise BenchmarkIsolationError("anonymous descriptor sealing is unavailable")
                seal_descriptor(descriptor, add_seals, seals)
            if descriptor != _PROVIDER_SECRET_FD:
                restore_from: Optional[int]
                restore_inheritable = False
                try:
                    os.fstat(_PROVIDER_SECRET_FD)
                except OSError:
                    restore_from = None
                else:
                    restore_inheritable = os.get_inheritable(_PROVIDER_SECRET_FD)
                    restore_from = os.dup(_PROVIDER_SECRET_FD)
                os.dup2(descriptor, _PROVIDER_SECRET_FD, inheritable=True)
                os.close(descriptor)
                descriptor = _PROVIDER_SECRET_FD
                handoff = _ProviderFdHandoff(
                    descriptor=descriptor,
                    restore_from=restore_from,
                    restore_inheritable=restore_inheritable,
                )
            else:
                handoff = _ProviderFdHandoff(descriptor=descriptor)
            os.set_inheritable(descriptor, True)
            return handoff
        except BaseException:
            if handoff is not None:
                self._close_provider_handoffs((handoff,))
            else:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise

    @staticmethod
    def _close_provider_handoffs(
        handoffs: Iterable[_ProviderFdHandoff],
    ) -> bool:
        failed = False
        for handoff in tuple(handoffs):
            if handoff.restore_from is None:
                try:
                    os.close(handoff.descriptor)
                except OSError:
                    failed = True
                continue
            try:
                os.dup2(
                    handoff.restore_from,
                    handoff.descriptor,
                    inheritable=handoff.restore_inheritable,
                )
            except OSError:
                failed = True
                # A failed restoration must not leave the credential-bearing
                # descriptor live.  Closing it is the only fail-closed state;
                # the caller will reject the phase because this method returns
                # false.
                try:
                    os.close(handoff.descriptor)
                except OSError:
                    pass
            finally:
                try:
                    os.close(handoff.restore_from)
                except OSError:
                    failed = True
        return not failed

    def _inspect(self, argv: Sequence[str], *, context: str) -> Dict[str, Any]:
        result = self._invoke(argv)
        if result.returncode != 0:
            raise BenchmarkIsolationError(f"{context} failed ({result.returncode})")
        return _json_object(str(result.stdout or ""), context=context)

    @staticmethod
    def _proxy_log_driver_none(proxy: Mapping[str, Any]) -> bool:
        log_config = _nested(proxy, "HostConfig", "LogConfig")
        return bool(
            isinstance(log_config, Mapping)
            and str(log_config.get("Type") or "").lower() == "none"
            and (log_config.get("Config") in ({}, None))
        )

    def _validate_proxy_against_expected_attestation(self, proxy: Mapping[str, Any]) -> None:
        expected = self.expected_proxy_attestation
        if not expected:
            raise BenchmarkIsolationError("expected proxy attestation is unavailable")
        proxy_id = str(proxy.get("Id") or proxy.get("ID") or "").lower()
        proxy_name = str(proxy.get("Name") or "").lstrip("/")
        config = _nested(proxy, "Config")
        host_config = _nested(proxy, "HostConfig")
        networks = _container_networks(proxy)
        if not isinstance(config, Mapping) or not isinstance(host_config, Mapping):
            raise BenchmarkIsolationError("model endpoint proxy metadata is incomplete")
        args = proxy.get("Args")
        if not isinstance(args, list) or any(not isinstance(value, str) for value in args):
            raise BenchmarkIsolationError("model endpoint proxy command metadata is invalid")
        path = str(proxy.get("Path") or "")
        if (
            _FULL_OCI_ID_RE.fullmatch(proxy_id) is None
            or proxy_id != expected.get("proxy_container_id")
            or proxy_name != expected.get("proxy_container")
            or str(proxy.get("Image") or "") != expected.get("image_id")
            or str(proxy.get("ImageName") or config.get("Image") or "") != expected.get("image_ref")
            or path != "python3"
        ):
            raise BenchmarkIsolationError("model endpoint proxy immutable identity does not match")
        labels = _labels(config.get("Labels"))
        expected_labels = {
            **self._image_labels,
            _PROXY_LABEL_ROLE: "model-endpoint-proxy",
            _PROXY_LABEL_SHA: str(expected["network_policy_sha256"]),
            "io.zscope.relay-sha256": str(expected["relay_sha256"]),
            "io.zscope.relay-projection-sha256": str(expected["relay_projection_sha256"]),
            "io.zscope.upstreams-sha256": str(expected["upstreams_sha256"]),
        }
        if labels != expected_labels or _nested(proxy, "State", "Running") is not True:
            raise BenchmarkIsolationError("model endpoint proxy attested labels are invalid")
        environment, environment_parsed = _environment_entries(config.get("Env"))
        if not environment_parsed or any(_is_secret_environment_key(key) for key in environment):
            raise BenchmarkIsolationError("model endpoint proxy exposes credential metadata")
        if args.count("--upstream") != expected.get("upstream_count"):
            raise BenchmarkIsolationError("model endpoint proxy upstream identity is invalid")
        cap_drop = _normalized_capabilities(host_config.get("CapDrop"))
        cap_add = _normalized_capabilities(host_config.get("CapAdd"))
        security_options = host_config.get("SecurityOpt")
        tmpfs = host_config.get("Tmpfs")
        log_config = host_config.get("LogConfig")
        if (
            host_config.get("ReadonlyRootfs") is not True
            or host_config.get("Privileged") is not False
            or cap_drop != ["ALL"]
            or cap_add != ["NET_BIND_SERVICE"]
            or security_options != ["no-new-privileges"]
            or host_config.get("PidsLimit") != 64
            or config.get("User") != "65532:65532"
            or not self._proxy_log_driver_none(proxy)
            or not isinstance(log_config, Mapping)
            or not isinstance(tmpfs, Mapping)
            or set(tmpfs) != {"/tmp"}
        ):
            raise BenchmarkIsolationError("model endpoint proxy security identity is invalid")
        network_names = sorted(networks)
        if network_names != expected.get("network_names"):
            raise BenchmarkIsolationError("model endpoint proxy network identity is invalid")
        internal = networks.get(str(expected.get("network_name")))
        egress = networks.get(str(expected.get("egress_network_name")))
        internal_aliases = internal.get("Aliases") if isinstance(internal, Mapping) else None
        egress_aliases = egress.get("Aliases") if isinstance(egress, Mapping) else None
        if internal_aliases != [expected.get("endpoint_host")] or egress_aliases != [
            expected.get("proxy_container")
        ]:
            raise BenchmarkIsolationError("model endpoint proxy aliases are invalid")
        mounts = proxy.get("Mounts")
        if not isinstance(mounts, list):
            raise BenchmarkIsolationError("model endpoint proxy mounts are invalid")
        relay_mounts = [
            row
            for row in mounts
            if isinstance(row, Mapping)
            and str(row.get("Type") or row.get("type") or "").lower() == "bind"
            and str(row.get("Destination") or row.get("destination") or "")
            == "/opt/zscope/p6_tcp_relay.py"
            and row.get("RW", row.get("rw")) is False
        ]
        unexpected = [
            row
            for row in mounts
            if not isinstance(row, Mapping)
            or str(row.get("Type") or row.get("type") or "").lower() not in {"bind", "tmpfs"}
            or (
                str(row.get("Type") or row.get("type") or "").lower() == "bind"
                and str(row.get("Destination") or row.get("destination") or "")
                != "/opt/zscope/p6_tcp_relay.py"
            )
            or (
                str(row.get("Type") or row.get("type") or "").lower() == "tmpfs"
                and str(row.get("Destination") or row.get("destination") or "") != "/tmp"
            )
        ]
        if len(relay_mounts) != 1 or unexpected:
            raise BenchmarkIsolationError("model endpoint proxy mount identity is invalid")
        relay_sha256, relay_projection_sha256 = _regular_file_identity(
            Path(str(relay_mounts[0].get("Source") or relay_mounts[0].get("source") or ""))
        )
        if relay_sha256 != expected.get("relay_sha256") or relay_projection_sha256 != expected.get(
            "relay_projection_sha256"
        ):
            raise BenchmarkIsolationError("model endpoint proxy relay identity is invalid")
        aliases = {
            str(expected["network_name"]): list(internal_aliases),
            str(expected["egress_network_name"]): list(egress_aliases),
        }
        projections = {
            "network_names": network_names,
            "network_aliases_sha256": _canonical_sha256(
                {"network_names": network_names, "aliases": aliases}
            ),
            "command_projection_sha256": _canonical_sha256({"path": path, "args": args}),
            "expected_environment_sha256": _canonical_sha256(
                {"environment": dict(sorted(environment.items()))}
            ),
            "security_projection_sha256": _canonical_sha256(
                {
                    "user": config.get("User"),
                    "read_only_rootfs": host_config.get("ReadonlyRootfs"),
                    "privileged": host_config.get("Privileged"),
                    "security_opt": list(security_options),
                    "pids_limit": host_config.get("PidsLimit"),
                    "cap_drop": cap_drop,
                    "cap_add": cap_add,
                    "tmpfs": {"/tmp": _normalized_tmpfs_options(tmpfs.get("/tmp"))},
                    "relay_mount": {
                        "destination": "/opt/zscope/p6_tcp_relay.py",
                        "read_only": True,
                        "relay_projection_sha256": relay_projection_sha256,
                    },
                }
            ),
            "log_driver_projection_sha256": _canonical_sha256(dict(log_config)),
        }
        proxy_projection = _canonical_sha256(
            {
                "proxy_container": proxy_name,
                "proxy_container_id": proxy_id,
                "image_ref": expected["image_ref"],
                "image_id": proxy.get("Image"),
                "endpoint_host": expected["endpoint_host"],
                **projections,
            }
        )
        if any(projections[field] != expected.get(field) for field in projections) or (
            proxy_projection != expected.get("proxy_inspect_projection_sha256")
        ):
            raise BenchmarkIsolationError("model endpoint proxy live projection is invalid")

    def _network_membership(
        self,
        network_inspect: Mapping[str, Any],
        *,
        context: str,
    ) -> tuple[Dict[str, Dict[str, Any]], str]:
        inspect_peers = _network_peers(network_inspect)
        if self.runtime_family != "podman":
            snapshot: Dict[str, Any] = {
                "source": "network-inspect",
                "network": self.network_policy.network_name,
                "peer_ids": sorted(inspect_peers),
            }
            return inspect_peers, _canonical_sha256(snapshot)

        argv = [
            self.runtime_path,
            "ps",
            "--all",
            "--no-trunc",
            "--filter",
            f"network={self.network_policy.network_name}",
            "--format",
            "json",
        ]
        result = self._invoke(argv)
        if result.returncode != 0:
            raise BenchmarkIsolationError(f"{context} failed ({result.returncode})")
        rows = _json_array(str(result.stdout or ""), context=context)
        peers: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            identity = str(row.get("Id") or row.get("ID") or row.get("id") or "")
            raw_networks = row.get("Networks") or row.get("networks")
            if isinstance(raw_networks, str):
                networks = {value.strip() for value in raw_networks.split(",") if value.strip()}
            elif isinstance(raw_networks, list):
                networks = {str(value) for value in raw_networks if str(value)}
            else:
                networks = set()
            if (
                _FULL_OCI_ID_RE.fullmatch(identity) is None
                or self.network_policy.network_name not in networks
            ):
                raise BenchmarkIsolationError(
                    f"{context} returned an unbound or unidentified container"
                )
            if identity in peers:
                raise BenchmarkIsolationError(f"{context} returned duplicate container IDs")
            peers[identity] = row

        if inspect_peers and (len(inspect_peers) != len(peers) or set(inspect_peers) != set(peers)):
            raise BenchmarkIsolationError(
                f"{context} disagrees with the runtime network inspection"
            )
        snapshot = {
            "source": "podman-ps-network-filter",
            "network": self.network_policy.network_name,
            "containers": rows,
        }
        return peers, _canonical_sha256(snapshot)

    def _preserve_fd_canary(self) -> str:
        payload = os.urandom(32)
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        safe_phase = "fd-canary"
        name = f"zscope-benchmark-{safe_phase}-{uuid.uuid4().hex[:12]}"
        argv = [
            self.runtime_path,
            "run",
            "--name",
            name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--log-driver=none",
            "--network=none",
            "--label",
            "io.zscope.role=scanner",
            "--label",
            f"{_NETWORK_LABEL_SHA}={self.network_policy.policy_sha256}",
        ]
        if self.p6_cleanup_scope is not None:
            for key, value in self.p6_cleanup_scope.labels(safe_phase).items():
                argv.extend(("--label", f"{key}={value}"))
        handoff: Optional[_ProviderFdHandoff] = None
        cid_directory: Optional[Path] = None
        cidfile: Optional[Path] = None
        container_id = ""
        run_succeeded = False
        cleanup_succeeded = False
        handoff_closed = False
        cid_cleanup_succeeded = False
        try:
            cid_directory = self._create_cidfile_directory()
            cidfile = cid_directory / "container.cid"
            handoff = self._create_anonymous_handoff(
                name=f"zscope-preserve-fd-canary-{uuid.uuid4().hex[:16]}",
                payload=payload,
            )
            argv.extend(
                (
                    "--cidfile",
                    str(cidfile),
                    "--preserve-fds=1",
                    self.image,
                    "python3",
                    "-c",
                    _PRESERVE_FD_CANARY_WRAPPER,
                    payload_sha256,
                )
            )
            result = self._invoke(argv, pass_fds=(handoff.descriptor,))
            container_id = self._read_container_id(cidfile)
            run_succeeded = result.returncode == 0
        except BaseException:
            run_succeeded = False
        finally:
            try:
                if not container_id and cidfile is not None:
                    container_id = self._read_container_id(cidfile)
                cleanup_succeeded = (
                    bool(container_id)
                    and self._invoke((self.runtime_path, "rm", "--force", container_id)).returncode
                    == 0
                )
            except BaseException:
                cleanup_succeeded = False
            if handoff is not None:
                handoff_closed = self._close_provider_handoffs((handoff,))
            cid_cleanup_succeeded = self._remove_cidfile_directory(cid_directory, cidfile)
        if not (run_succeeded and cleanup_succeeded and handoff_closed and cid_cleanup_succeeded):
            raise BenchmarkIsolationError("OCI anonymous descriptor canary failed")
        return _canonical_sha256(
            {
                "schema_version": "zscope.oci-preserve-fd-canary.v1",
                "image": self.image,
                "network": "none",
                "log_driver": "none",
                "preserved_descriptor_count": 1,
                "wrapper_sha256": hashlib.sha256(
                    _PRESERVE_FD_CANARY_WRAPPER.encode("utf-8")
                ).hexdigest(),
                "payload_sha256": payload_sha256,
                "result": "verified",
            }
        )

    def _live_provider_boundary(self) -> Dict[str, Any]:
        """Revalidate exact proxy/network identity immediately before key creation."""

        self._verify_expected_proxy_attestation_integrity()
        proxy = self._inspect(
            (self.runtime_path, "inspect", self.network_policy.proxy_container),
            context="live model proxy inspect",
        )
        self._validate_proxy_against_expected_attestation(proxy)
        network = self._inspect(
            (self.runtime_path, "network", "inspect", self.network_policy.network_name),
            context="live OCI network inspect",
        )
        internal = network.get("Internal")
        if internal is None:
            internal = network.get("internal")
        labels = _labels(network.get("Labels") or network.get("labels"))
        peers, membership_sha256 = self._network_membership(
            network,
            context="live OCI network membership inspect",
        )
        expected_proxy_id = str(self.expected_proxy_attestation.get("proxy_container_id") or "")
        if (
            internal is not True
            or labels.get(_NETWORK_LABEL_MODE) != "model-endpoint-only"
            or labels.get(_NETWORK_LABEL_SHA) != self.network_policy.policy_sha256
            or set(peers) != {expected_proxy_id}
        ):
            raise BenchmarkIsolationError("live provider isolation boundary is invalid")
        return {
            "verified": True,
            "proxy_container_id": expected_proxy_id,
            "proxy_inspect_sha256": _inspect_projection_sha256(proxy),
            "network_inspect_sha256": _canonical_sha256(network),
            "network_membership_sha256": membership_sha256,
        }

    def preflight(self) -> Dict[str, Any]:
        try:
            return self._preflight_retaining_credentials()
        except BaseException:
            self._clear_provider_credentials()
            raise

    def _preflight_retaining_credentials(self) -> Dict[str, Any]:
        if self._preflight is not None:
            return dict(self._preflight)
        self._verify_expected_proxy_attestation_integrity()
        info_argv = (
            [self.runtime_path, "info", "--format", "json"]
            if self.runtime_family == "podman"
            else [self.runtime_path, "info", "--format", "{{json .}}"]
        )
        info = self._inspect(info_argv, context="OCI runtime info")
        if not _is_rootless_info(self.runtime_family, info):
            raise BenchmarkIsolationError("OCI runtime is not verified rootless")
        preserve_fds_verified = False
        if self.runtime_family == "podman":
            preserve_help = self._invoke((self.runtime_path, "run", "--help"))
            preserve_fds_verified = bool(
                preserve_help.returncode == 0
                and "--preserve-fds" in str(preserve_help.stdout or "")
            )
        if (
            self.credential_environment_keys
            and not self._bootstrap_preflight_only
            and not preserve_fds_verified
        ):
            raise BenchmarkIsolationError("OCI runtime lacks anonymous descriptor preservation")

        image_inspect = self._inspect(
            [self.runtime_path, "image", "inspect", self.image],
            context="OCI image inspect",
        )
        expected_digest = self.image.rsplit("@", 1)[1]
        image_id = str(image_inspect.get("Id") or image_inspect.get("ID") or "")
        if not image_id:
            raise BenchmarkIsolationError("OCI image inspect did not return an immutable image ID")
        digest_values: list[str] = []
        for key in ("RepoDigests", "Digest", "digest"):
            digest_values.extend(_strings(image_inspect.get(key)))
        if not any(
            value == expected_digest or value.endswith("@" + expected_digest)
            for value in digest_values
        ):
            raise BenchmarkIsolationError("OCI image inspect did not verify the pinned digest")
        image_environment, image_environment_parsed = _environment_entries(
            _nested(image_inspect, "Config", "Env")
        )
        if not image_environment_parsed:
            raise BenchmarkIsolationError("OCI image environment metadata is invalid")
        image_environment_unset_keys = tuple(
            sorted(key for key in image_environment if _is_secret_environment_key(key))
        )
        retained_image_environment = {
            key: value
            for key, value in image_environment.items()
            if key not in image_environment_unset_keys
        }
        raw_image_labels = _nested(image_inspect, "Config", "Labels")
        if not isinstance(raw_image_labels, Mapping):
            raise BenchmarkIsolationError("OCI image label metadata is invalid")
        self._image_labels = _labels(raw_image_labels)
        image_projection_sha256 = _canonical_sha256(
            {
                "image_ref": self.image,
                "image_id": image_id,
                "image_digest": expected_digest,
                "labels": self._image_labels,
                "environment": dict(sorted(retained_image_environment.items())),
                "unset_environment_keys": list(image_environment_unset_keys),
            }
        )
        if image_id != self.expected_proxy_attestation.get(
            "image_id"
        ) or image_projection_sha256 != self.expected_proxy_attestation.get(
            "image_inspect_projection_sha256"
        ):
            raise BenchmarkIsolationError("OCI image live projection does not match")
        if image_environment_unset_keys and self.runtime_family != "podman":
            raise BenchmarkIsolationError(
                "OCI runtime cannot remove inherited credential-shaped image environment"
            )
        self._image_environment_unset_keys = image_environment_unset_keys

        network = self._inspect(
            [self.runtime_path, "network", "inspect", self.network_policy.network_name],
            context="OCI network inspect",
        )
        internal = network.get("Internal")
        if internal is None:
            internal = network.get("internal")
        labels = _labels(network.get("Labels") or network.get("labels"))
        if internal is not True:
            raise BenchmarkIsolationError("formal OCI network must be internal")
        if labels.get(_NETWORK_LABEL_MODE) != "model-endpoint-only":
            raise BenchmarkIsolationError("OCI network lacks the endpoint-only policy label")
        if labels.get(_NETWORK_LABEL_SHA) != self.network_policy.policy_sha256:
            raise BenchmarkIsolationError("OCI network policy digest does not match the request")

        proxy = self._inspect(
            [self.runtime_path, "inspect", self.network_policy.proxy_container],
            context="model proxy inspect",
        )
        proxy_id = str(proxy.get("Id") or proxy.get("ID") or "")
        if self.expected_proxy_attestation:
            self._validate_proxy_against_expected_attestation(proxy)
        proxy_labels = _labels(_nested(proxy, "Config", "Labels"))
        proxy_credential_metadata_safe = _credential_metadata_safe(_nested(proxy, "Config", "Env"))
        proxy_network = _container_networks(proxy).get(self.network_policy.network_name)
        proxy_running = _nested(proxy, "State", "Running") is True
        aliases = []
        if isinstance(proxy_network, Mapping):
            aliases = [str(value).lower() for value in proxy_network.get("Aliases") or []]
        if (
            _FULL_OCI_ID_RE.fullmatch(proxy_id.lower()) is None
            or not proxy_running
            or not isinstance(proxy_network, Mapping)
        ):
            raise BenchmarkIsolationError(
                "model endpoint proxy is not running on the policy network"
            )
        if proxy_labels.get(_PROXY_LABEL_ROLE) != "model-endpoint-proxy":
            raise BenchmarkIsolationError("model endpoint proxy role is not attested")
        if proxy_labels.get(_PROXY_LABEL_SHA) != self.network_policy.policy_sha256:
            raise BenchmarkIsolationError("model endpoint proxy policy digest does not match")
        if not proxy_credential_metadata_safe:
            raise BenchmarkIsolationError(
                "model endpoint proxy exposes credential metadata in OCI configuration"
            )
        if self.network_policy.endpoint_host not in aliases:
            raise BenchmarkIsolationError("model endpoint hostname is not a proxy network alias")
        peers, network_membership_sha256 = self._network_membership(
            network, context="OCI network membership inspect"
        )
        if len(peers) != 1 or set(peers) != {proxy_id}:
            raise BenchmarkIsolationError(
                "endpoint-only network must contain exactly the declared proxy before execution"
            )

        preserve_fds_canary_sha256 = (
            self._preserve_fd_canary()
            if self.credential_environment_keys and not self._bootstrap_preflight_only
            else ""
        )
        self._preflight = {
            "runtime_info_sha256": _canonical_sha256(info),
            "image_inspect_sha256": _canonical_sha256(image_inspect),
            "image_inspect_projection_sha256": image_projection_sha256,
            "image_id": image_id,
            "image_environment_unset_keys": list(image_environment_unset_keys),
            "network_inspect_sha256": _canonical_sha256(network),
            "network_membership_sha256": network_membership_sha256,
            "proxy_inspect_sha256": _inspect_projection_sha256(proxy),
            "rootless_verified": True,
            "preserve_fds_verified": preserve_fds_verified,
            "preserve_fds_canary_verified": bool(preserve_fds_canary_sha256),
            "preserve_fds_canary_sha256": preserve_fds_canary_sha256,
            "image_digest_verified": True,
            "network_internal": True,
            "network_policy_sha256": self.network_policy.policy_sha256,
            "network_name": self.network_policy.network_name,
            "endpoint_origin": self.network_policy.endpoint_origin,
            "provider_identity_sha256": self.provider_identity_sha256,
            "proxy_credential_metadata_safe": True,
            "proxy_container_id": proxy_id,
            "proxy_attestation_file_sha256": self.expected_proxy_attestation_file_sha256,
            "proxy_attestation_content_sha256": str(
                self.expected_proxy_attestation.get("content_sha256") or ""
            ),
            "proxy_attestation_verified": bool(self.expected_proxy_attestation),
            "proxy_attestation_bootstrap_preflight_only": self._bootstrap_preflight_only,
            "proxy_running": True,
        }
        return dict(self._preflight)

    def _actual_mounts(self, inspect: Mapping[str, Any]) -> list[Dict[str, Any]]:
        expected = {
            "/zscope-input": "scan_input",
            "/zscope-output": "artifact_output",
            "/zscope-cache": "cache",
            **(
                {"/zscope-runtime/zscope": "runtime_source"}
                if self.runtime_source is not None
                else {}
            ),
        }
        result = []
        for raw in inspect.get("Mounts") or []:
            if not isinstance(raw, Mapping):
                continue
            destination = str(raw.get("Destination") or raw.get("destination") or "")
            source = str(raw.get("Source") or raw.get("source") or "")
            read_only = raw.get("RW") is False
            if "RW" not in raw:
                read_only = bool(raw.get("ReadOnly") or raw.get("read_only"))
            result.append(
                {
                    "source": str(Path(source).resolve()) if source else "",
                    "destination": destination,
                    "purpose": expected.get(destination, "unexpected"),
                    "read_only": read_only,
                    "type": str(raw.get("Type") or raw.get("type") or ""),
                }
            )
        return result

    def _phase_evidence(
        self,
        *,
        phase: str,
        name: str,
        expected_container_id: str,
        run_result: subprocess.CompletedProcess[str],
        accepted_returncodes: Sequence[int],
        expected_credential_keys: Sequence[str],
        provider_boundary: Mapping[str, Any],
        directory_binding_sha256: str,
    ) -> Dict[str, Any]:
        inspect = self._inspect(
            [self.runtime_path, "inspect", expected_container_id],
            context=f"{phase} container inspect",
        )
        proxy = self._inspect(
            [self.runtime_path, "inspect", self.network_policy.proxy_container],
            context=f"{phase} model proxy inspect",
        )
        network = self._inspect(
            [self.runtime_path, "network", "inspect", self.network_policy.network_name],
            context=f"{phase} network inspect",
        )
        container_id = str(inspect.get("Id") or inspect.get("ID") or "")
        working_dir = str(_nested(inspect, "Config", "WorkingDir") or "")
        readonly_rootfs = _nested(inspect, "HostConfig", "ReadonlyRootfs") is True
        cap_drop = _nested(inspect, "HostConfig", "CapDrop") or []
        security_opt = _nested(inspect, "HostConfig", "SecurityOpt") or []
        effective_caps = inspect.get("EffectiveCaps")
        networks = _container_networks(inspect)
        state_exit = _nested(inspect, "State", "ExitCode")
        mounts = self._actual_mounts(inspect)
        expected_sources = {
            (str(self.scan_input), "/zscope-input", True),
            (str(self.artifact_output), "/zscope-output", False),
            (str(self.cache_output), "/zscope-cache", False),
            *(
                {(str(self.runtime_source), "/zscope-runtime/zscope", True)}
                if self.runtime_source is not None
                else set()
            ),
        }
        actual_sources = {
            (str(row["source"]), str(row["destination"]), bool(row["read_only"])) for row in mounts
        }
        peers, network_membership_sha256 = self._network_membership(
            network, context=f"{phase} network membership inspect"
        )
        proxy_id = str(_as_mapping(self._preflight).get("proxy_container_id") or "")
        proxy_current_id = str(proxy.get("Id") or proxy.get("ID") or "")
        if self.expected_proxy_attestation:
            self._verify_expected_proxy_attestation_integrity()
            self._validate_proxy_against_expected_attestation(proxy)
        proxy_labels = _labels(_nested(proxy, "Config", "Labels"))
        proxy_credential_metadata_safe = _credential_metadata_safe(_nested(proxy, "Config", "Env"))
        proxy_network = _container_networks(proxy).get(self.network_policy.network_name)
        proxy_aliases = (
            [str(value).lower() for value in proxy_network.get("Aliases") or []]
            if isinstance(proxy_network, Mapping)
            else []
        )
        proxy_verified = bool(
            proxy_current_id == proxy_id
            and _FULL_OCI_ID_RE.fullmatch(proxy_current_id.lower()) is not None
            and _nested(proxy, "State", "Running") is True
            and isinstance(proxy_network, Mapping)
            and proxy_labels.get(_PROXY_LABEL_ROLE) == "model-endpoint-proxy"
            and proxy_labels.get(_PROXY_LABEL_SHA) == self.network_policy.policy_sha256
            and proxy_credential_metadata_safe
            and self.network_policy.endpoint_host in proxy_aliases
        )
        network_internal = network.get("Internal")
        if network_internal is None:
            network_internal = network.get("internal")
        network_labels = _labels(network.get("Labels") or network.get("labels"))
        network_contract_verified = bool(
            network_internal is True
            and network_labels.get(_NETWORK_LABEL_MODE) == "model-endpoint-only"
            and network_labels.get(_NETWORK_LABEL_SHA) == self.network_policy.policy_sha256
            and proxy_verified
        )
        peer_ids_valid = bool(len(peers) == 2 and set(peers) == {container_id, proxy_id})
        runtime_network_mode = str(_nested(inspect, "HostConfig", "NetworkMode") or "")
        network_attachment_verified = set(networks) == {self.network_policy.network_name}
        # Podman 4.x reports ``bridge`` in HostConfig.NetworkMode even when the
        # inspected NetworkSettings map and the runtime membership query bind the
        # container to one explicit user network.  Treat those two independent
        # runtime facts as authoritative while retaining the raw mode for audit.
        network_mode = runtime_network_mode
        if network_attachment_verified and (
            not runtime_network_mode or self.runtime_family == "podman"
        ):
            network_mode = self.network_policy.network_name
        image_ref = str(_nested(inspect, "Config", "Image") or "")
        container_image_id = str(inspect.get("Image") or inspect.get("ImageID") or "")
        expected_image_id = str(_as_mapping(self._preflight).get("image_id") or "")
        image_verified = bool(
            image_ref and _image_identity_matches(container_image_id, expected_image_id)
        )
        scanner_labels = _labels(_nested(inspect, "Config", "Labels"))
        expected_cleanup_labels = (
            self.p6_cleanup_scope.labels(phase) if self.p6_cleanup_scope is not None else {}
        )
        p6_cleanup_scope_verified = bool(
            self.p6_cleanup_scope is not None
            and all(
                scanner_labels.get(key) == value for key, value in expected_cleanup_labels.items()
            )
        )
        scanner_labels_verified = bool(
            scanner_labels.get(_PROXY_LABEL_ROLE) == "scanner"
            and scanner_labels.get(_NETWORK_LABEL_SHA) == self.network_policy.policy_sha256
            and (self.p6_cleanup_scope is None or p6_cleanup_scope_verified)
        )
        scanner_name = str(inspect.get("Name") or "").lstrip("/")
        scanner_environment, scanner_environment_parsed = _environment_entries(
            _nested(inspect, "Config", "Env")
        )
        credential_keys = {str(key) for key in expected_credential_keys}
        provider_pre_handoff_verified = bool(
            not credential_keys
            or (
                provider_boundary.get("verified") is True
                and provider_boundary.get("proxy_container_id") == proxy_id
            )
        )
        log_driver_none_verified = self._proxy_log_driver_none(inspect)
        scanner_provider_anonymous_fd_verified = bool(
            not credential_keys
            or (
                credential_keys == {"Z_SCOPE_API_KEY"}
                and _as_mapping(self._preflight).get("preserve_fds_verified") is True
                and _as_mapping(self._preflight).get("preserve_fds_canary_verified") is True
            )
        )
        scanner_provider_environment_verified = bool(
            scanner_environment_parsed
            and not any(_is_secret_environment_key(key) for key in scanner_environment)
            and scanner_provider_anonymous_fd_verified
            and log_driver_none_verified
        )
        normalized_cap_drop = {str(value).upper() for value in cap_drop}
        cap_drop_verified = bool(
            "ALL" in normalized_cap_drop
            or (isinstance(effective_caps, list) and not effective_caps)
            or (
                self.runtime_family == "podman"
                and _PODMAN_V4_DEFAULT_CAPABILITIES.issubset(normalized_cap_drop)
            )
        )
        security_verified = bool(
            readonly_rootfs
            and cap_drop_verified
            and any("no-new-privileges" in str(value).lower() for value in security_opt)
        )
        inspect_verified = bool(
            container_id == expected_container_id
            and _FULL_OCI_ID_RE.fullmatch(container_id) is not None
            and scanner_name == name
            and working_dir == "/zscope-input"
            and expected_sources == actual_sources
            and all(row.get("type") in {"bind", ""} for row in mounts)
            and network_mode == self.network_policy.network_name
            and network_attachment_verified
            and peer_ids_valid
            and network_contract_verified
            and scanner_labels_verified
            and scanner_provider_environment_verified
            and provider_pre_handoff_verified
            and image_verified
            and security_verified
            and isinstance(state_exit, int)
            and state_exit == run_result.returncode
            and state_exit in set(accepted_returncodes)
        )
        return {
            "phase": phase,
            "container_name": name,
            "container_id": container_id,
            "command_return_code": int(run_result.returncode),
            "container_exit_code": state_exit,
            "accepted_returncodes": list(accepted_returncodes),
            "working_dir": working_dir,
            "image": image_ref,
            "image_id": container_image_id,
            "image_verified": image_verified,
            "read_only_rootfs": readonly_rootfs,
            "cap_drop": list(cap_drop) if isinstance(cap_drop, list) else [],
            "cap_drop_verified": cap_drop_verified,
            "security_opt": list(security_opt) if isinstance(security_opt, list) else [],
            "security_verified": security_verified,
            "scanner_labels_verified": scanner_labels_verified,
            "p6_cleanup_scope_verified": p6_cleanup_scope_verified,
            "p6_workflow_run_id": (
                self.p6_cleanup_scope.workflow_run_id if self.p6_cleanup_scope is not None else ""
            ),
            "p6_workflow_run_attempt": (
                int(self.p6_cleanup_scope.workflow_run_attempt)
                if self.p6_cleanup_scope is not None
                else 0
            ),
            "p6_attempt_id": (
                self.p6_cleanup_scope.attempt_id if self.p6_cleanup_scope is not None else ""
            ),
            "p6_repository": (
                self.p6_cleanup_scope.repository if self.p6_cleanup_scope is not None else ""
            ),
            "p6_concurrency_group": (
                self.p6_cleanup_scope.concurrency_group if self.p6_cleanup_scope is not None else ""
            ),
            "p6_phase": (_safe_phase_name(phase) if self.p6_cleanup_scope is not None else ""),
            "scanner_provider_environment_verified": scanner_provider_environment_verified,
            "scanner_provider_environment_keys": sorted(credential_keys),
            "scanner_provider_metadata_safe": bool(
                scanner_environment_parsed
                and not any(_is_secret_environment_key(key) for key in scanner_environment)
            ),
            "scanner_provider_anonymous_fd_verified": scanner_provider_anonymous_fd_verified,
            "scanner_log_driver_none_verified": log_driver_none_verified,
            "provider_pre_handoff_verified": provider_pre_handoff_verified,
            "provider_pre_handoff_proxy_sha256": str(
                provider_boundary.get("proxy_inspect_sha256") or ""
            ),
            "provider_pre_handoff_network_sha256": str(
                provider_boundary.get("network_inspect_sha256") or ""
            ),
            "provider_pre_handoff_membership_sha256": str(
                provider_boundary.get("network_membership_sha256") or ""
            ),
            "directory_binding_sha256": directory_binding_sha256,
            # The runner persists only the fixed zscope.oci-phase-log.v1
            # summary written by execute_phase.  Captured runtime streams stay
            # in memory long enough to inspect protocol state and are never
            # copied into the phase artifact.
            "stdout_persisted": False,
            "stderr_persisted": False,
            "mounts": mounts,
            "unexpected_mount_count": sum(row["purpose"] == "unexpected" for row in mounts),
            "network_name": network_mode,
            "runtime_network_mode": runtime_network_mode,
            "network_attachment_verified": network_attachment_verified,
            "network_peer_count": len(peers),
            "network_peers_verified": peer_ids_valid,
            "network_internal": network_internal is True,
            "network_contract_verified": network_contract_verified,
            "proxy_verified": proxy_verified,
            "proxy_credential_metadata_safe": proxy_credential_metadata_safe,
            "provider_identity_sha256": self.provider_identity_sha256,
            "container_inspect_sha256": _inspect_projection_sha256(inspect),
            "proxy_inspect_sha256": _inspect_projection_sha256(proxy),
            "network_inspect_sha256": _canonical_sha256(network),
            "network_membership_sha256": network_membership_sha256,
            "inspect_verified": inspect_verified,
        }

    def execute_phase(
        self,
        phase: str,
        command: Sequence[str],
        *,
        log_path: Path,
        accepted_returncodes: Sequence[int] = (0,),
        provider_credentials: bool = True,
    ) -> OciPhaseResult:
        import time

        if self._bootstrap_preflight_only and (phase != "preflight" or provider_credentials):
            self._clear_provider_credentials()
            raise BenchmarkIsolationError(
                "bootstrap proxy attestation permits only credential-free preflight"
            )
        self.preflight()
        self._verify_runtime_source_integrity()
        self._verify_expected_proxy_attestation_integrity()
        if not phase or not command:
            self._clear_provider_credentials()
            raise BenchmarkIsolationError("OCI phase and command must be non-empty")
        command_text = json.dumps([str(value) for value in command]).lower()
        if "ground_truth" in command_text or "benchmark/" in command_text:
            self._clear_provider_credentials()
            raise BenchmarkIsolationError("scan command references benchmark answer material")
        safe_phase = _safe_phase_name(phase)
        name = f"zscope-benchmark-{safe_phase}-{uuid.uuid4().hex[:12]}"
        argv = [
            self.runtime_path,
            "run",
            "--name",
            name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--log-driver=none",
            "--workdir",
            "/zscope-input",
            "--mount",
            f"type=bind,src={self.scan_input},dst=/zscope-input,readonly",
            "--mount",
            f"type=bind,src={self.artifact_output},dst=/zscope-output",
            "--mount",
            f"type=bind,src={self.cache_output},dst=/zscope-cache",
            *(
                (
                    "--mount",
                    f"type=bind,src={self.runtime_source},dst=/zscope-runtime/zscope,readonly",
                )
                if self.runtime_source is not None
                else ()
            ),
            "--network",
            self.network_policy.network_name,
            "--label",
            "io.zscope.role=scanner",
            "--label",
            f"{_NETWORK_LABEL_SHA}={self.network_policy.policy_sha256}",
        ]
        if self.p6_cleanup_scope is not None:
            for key, value in self.p6_cleanup_scope.labels(safe_phase).items():
                argv.extend(("--label", f"{key}={value}"))
        for key in self._image_environment_unset_keys:
            argv.extend(("--unsetenv", key))
        expected_credential_keys = (
            tuple(self.credential_environment_keys) if provider_credentials else ()
        )
        if provider_credentials and any(
            not str(self._provider_environment.get(key) or "").strip()
            for key in expected_credential_keys
        ):
            self._clear_provider_credentials()
            raise BenchmarkIsolationError("provider credentials are unavailable for OCI phase")
        if provider_credentials:
            for key in self.container_environment_keys:
                if key not in expected_credential_keys:
                    argv.extend(("--env", f"{key}={self._provider_environment[key]}"))
        command_tail = (self.image, *(str(value) for value in command))
        try:
            _write_oci_phase_log(
                log_path,
                {
                    "schema_version": "zscope.oci-phase-log.v1",
                    "phase": safe_phase,
                    "outcome": "launching",
                    "return_code": None,
                    "return_code_accepted": False,
                    "stdout_persisted": False,
                    "stderr_persisted": False,
                },
            )
        except BaseException:
            self._clear_provider_credentials()
            raise
        protected_signals = tuple(
            value
            for value in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None))
            if isinstance(value, int)
        )
        previous_signal_handlers: Dict[int, Any] = {}

        def interrupt_phase(_signum: int, _frame: Any) -> None:
            for protected in previous_signal_handlers:
                try:
                    signal.signal(protected, signal.SIG_IGN)
                except (OSError, RuntimeError, ValueError):
                    pass
            raise _OciPhaseInterrupted()

        try:
            for protected in protected_signals:
                previous_signal_handlers[protected] = signal.getsignal(protected)
                signal.signal(protected, interrupt_phase)
        except (OSError, RuntimeError, ValueError):
            for protected, previous in previous_signal_handlers.items():
                try:
                    signal.signal(protected, previous)
                except (OSError, RuntimeError, ValueError):
                    pass
            self._clear_provider_credentials()
            raise BenchmarkIsolationError("OCI phase cancellation guard is unavailable") from None
        started = time.monotonic()
        cleanup_failed = True
        run_result: Optional[subprocess.CompletedProcess[str]] = None
        phase_evidence: Optional[Dict[str, Any]] = None
        provider_handoffs: Dict[str, _ProviderFdHandoff] = {}
        provider_boundary: Dict[str, Any] = {}
        directory_bindings: Dict[str, _DirectoryBinding] = {}
        directory_binding_sha256 = ""
        cid_directory: Optional[Path] = None
        cidfile: Optional[Path] = None
        container_id = ""
        run_attempted = False
        elapsed = 0.0
        try:
            try:
                directory_bindings = self._open_phase_directory_bindings()
                directory_binding_sha256 = self._verify_directory_bindings(directory_bindings)
                if expected_credential_keys:
                    provider_boundary = self._live_provider_boundary()
                cid_directory = self._create_cidfile_directory()
                cidfile = cid_directory / "container.cid"
                provider_handoffs = self._create_provider_handoffs(
                    phase=safe_phase,
                    credential_keys=expected_credential_keys,
                )
                run_argv = list(argv)
                mount_rows = {
                    "scan_input": ("/zscope-input", True),
                    "artifact_output": ("/zscope-output", False),
                    "cache": ("/zscope-cache", False),
                    **(
                        {"runtime_source": ("/zscope-runtime/zscope", True)}
                        if self.runtime_source is not None
                        else {}
                    ),
                }
                for purpose, (destination, read_only) in mount_rows.items():
                    binding = directory_bindings[purpose]
                    original = f"type=bind,src={binding.path},dst={destination}" + (
                        ",readonly" if read_only else ""
                    )
                    replacement = f"type=bind,src={binding.mount_source},dst={destination}" + (
                        ",readonly" if read_only else ""
                    )
                    try:
                        run_argv[run_argv.index(original)] = replacement
                    except ValueError:
                        raise BenchmarkIsolationError(
                            "OCI directory mount projection is invalid"
                        ) from None
                run_argv.extend(("--cidfile", str(cidfile)))
                if provider_handoffs:
                    run_argv.extend(
                        (
                            "--preserve-fds=1",
                            self.image,
                            "python3",
                            "-c",
                            _PROVIDER_SECRET_WRAPPER,
                            "--",
                            *(str(value) for value in command),
                        )
                    )
                else:
                    run_argv.extend(command_tail)
                run_attempted = True
                run_result = self._invoke(
                    run_argv,
                    pass_fds=tuple(handoff.descriptor for handoff in provider_handoffs.values())
                    + tuple(
                        binding.descriptor
                        for binding in directory_bindings.values()
                        if binding.descriptor is not None
                    ),
                )
                container_id = self._read_container_id(cidfile)
                if self._verify_directory_bindings(directory_bindings) != directory_binding_sha256:
                    raise BenchmarkIsolationError("OCI directory binding projection changed")
                elapsed = time.monotonic() - started
                accepted = tuple(int(value) for value in accepted_returncodes)
                _write_oci_phase_log(
                    log_path,
                    {
                        "schema_version": "zscope.oci-phase-log.v1",
                        "phase": safe_phase,
                        "outcome": "completed",
                        "return_code": int(run_result.returncode),
                        "return_code_accepted": int(run_result.returncode) in set(accepted),
                        "stdout_persisted": False,
                        "stderr_persisted": False,
                    },
                )
                phase_evidence = self._phase_evidence(
                    phase=phase,
                    name=name,
                    expected_container_id=container_id,
                    run_result=run_result,
                    accepted_returncodes=accepted,
                    expected_credential_keys=expected_credential_keys,
                    provider_boundary=provider_boundary,
                    directory_binding_sha256=directory_binding_sha256,
                )
            except BenchmarkIsolationError:
                raise
            except Exception:
                raise BenchmarkIsolationError(
                    f"OCI phase {safe_phase!r} runtime invocation failed"
                ) from None
        finally:
            try:
                for protected in previous_signal_handlers:
                    try:
                        signal.signal(protected, signal.SIG_IGN)
                    except (OSError, RuntimeError, ValueError):
                        pass
                try:
                    if run_attempted and not container_id and cidfile is not None:
                        container_id = self._read_container_id(cidfile)
                    if run_attempted:
                        cleanup_failed = bool(
                            not container_id
                            or self._invoke(
                                [self.runtime_path, "rm", "--force", container_id]
                            ).returncode
                            != 0
                        )
                    else:
                        cleanup_failed = False
                except BaseException:
                    cleanup_failed = True
                handoffs_closed = self._close_provider_handoffs(provider_handoffs.values())
                cleanup_failed = cleanup_failed or not handoffs_closed
                directories_closed = self._close_directory_bindings(directory_bindings.values())
                cleanup_failed = cleanup_failed or not directories_closed
                cleanup_failed = cleanup_failed or not self._remove_cidfile_directory(
                    cid_directory, cidfile
                )
                if not (
                    phase_evidence is not None and phase_evidence.get("inspect_verified") is True
                ):
                    self._clear_provider_credentials()
            finally:
                for protected, previous in previous_signal_handlers.items():
                    try:
                        signal.signal(protected, previous)
                    except (OSError, RuntimeError, ValueError):
                        pass
        if cleanup_failed:
            self._clear_provider_credentials()
            raise BenchmarkIsolationError(f"failed to remove inspected OCI container {name}")
        self._verify_runtime_source_integrity()
        assert run_result is not None
        assert phase_evidence is not None
        phase_evidence["cancellation_cleanup_guard_verified"] = True
        self._phases.append(phase_evidence)
        if phase_evidence.get("inspect_verified") is not True:
            self._clear_provider_credentials()
            raise BenchmarkIsolationError(f"OCI phase {phase!r} failed execution evidence checks")
        if provider_credentials and phase == "scan":
            self._clear_provider_credentials()
        return OciPhaseResult(
            phase=phase,
            seconds=elapsed,
            return_code=int(run_result.returncode),
            evidence=dict(phase_evidence),
        )

    def execution_evidence(self, *, required_phases: Sequence[str] = ()) -> Dict[str, Any]:
        try:
            self._verify_runtime_source_integrity()
            preflight = self.preflight()
        except Exception:
            self._clear_provider_credentials()
            raise
        required = {str(value) for value in required_phases}
        present = {str(row.get("phase") or "") for row in self._phases}
        phases_verified = bool(self._phases) and all(
            row.get("inspect_verified") is True for row in self._phases
        )
        phases_verified = phases_verified and required.issubset(present)
        mounts = list(self._phases[0].get("mounts") or []) if self._phases else []
        evidence = {
            "schema_version": ISOLATION_SCHEMA_VERSION,
            "mode": "oci",
            "runtime": self.runtime_family,
            "runtime_path": self.runtime_path,
            "image": self.image,
            "available": True,
            **preflight,
            "execution_verified": phases_verified,
            "actual_inspection_collected": phases_verified,
            "release_capable": phases_verified and not self._bootstrap_preflight_only,
            "bootstrap_preflight_only": self._bootstrap_preflight_only,
            "truth_mounted": False,
            "repository_mounted": False,
            "runtime_source_mounted": self.runtime_source is not None,
            "runtime_source_sha256": self.runtime_source_sha256,
            "scanner_cwd": "/zscope-input",
            "scanner_cwd_isolated": phases_verified,
            "mounts": mounts,
            "mounts_verified": phases_verified,
            "security_verified": phases_verified
            and all(row.get("security_verified") is True for row in self._phases),
            "network_mode": "model-endpoint-only",
            "network_restriction_verified": phases_verified
            and all(row.get("network_peers_verified") is True for row in self._phases),
            "phase_executions": [dict(row) for row in self._phases],
            "required_phases": sorted(required),
            "errors": ([] if phases_verified else ["required OCI phases are not fully verified"]),
        }
        self._clear_provider_credentials()
        return evidence


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def require_release_isolation(
    *,
    required: bool,
    capability: Optional[Mapping[str, Any]],
    repository_checkout: Optional[Path] = None,
    truth_paths: Sequence[Path] = (),
) -> None:
    if not required:
        return
    errors = validate_oci_execution_evidence(
        capability,
        repository_checkout=repository_checkout,
        truth_paths=truth_paths,
    )
    if errors:
        detail = "; ".join(errors)
        raise BenchmarkIsolationError(
            "release policy requires verified OCI answer isolation evidence"
            + (f": {detail}" if detail else "")
        )


def validate_oci_execution_evidence(
    evidence: Optional[Mapping[str, Any]],
    *,
    repository_checkout: Optional[Path] = None,
    truth_paths: Sequence[Path] = (),
    require_release_capable: bool = True,
) -> list[str]:
    """Return concrete reasons why OCI execution evidence is not release-safe."""

    if not isinstance(evidence, Mapping):
        return ["isolation evidence is missing"]
    raw_errors = evidence.get("errors")
    errors = (
        [str(item) for item in raw_errors]
        if isinstance(raw_errors, (list, tuple))
        else [str(raw_errors)] if raw_errors else []
    )
    if evidence.get("schema_version") != ISOLATION_SCHEMA_VERSION:
        errors.append("isolation evidence schema version is invalid")
    for key, expected in (
        ("mode", "oci"),
        ("available", True),
        ("rootless_verified", True),
        ("image_digest_verified", True),
        ("execution_verified", True),
        ("actual_inspection_collected", True),
        ("truth_mounted", False),
        ("repository_mounted", False),
        ("scanner_cwd_isolated", True),
        ("mounts_verified", True),
        ("security_verified", True),
        ("network_restriction_verified", True),
        ("proxy_credential_metadata_safe", True),
    ):
        if evidence.get(key) != expected:
            errors.append(f"{key} must be {expected!r}")
    if require_release_capable:
        if evidence.get("release_capable") is not True:
            errors.append("release_capable must be True")
        if evidence.get("bootstrap_preflight_only") is True:
            errors.append("release evidence cannot use bootstrap proxy attestation")
    else:
        if evidence.get("release_capable") is not False:
            errors.append("release_capable must be False for bootstrap preflight")
        if evidence.get("bootstrap_preflight_only") is not True:
            errors.append("bootstrap_preflight_only must be True")
    if not _PINNED_IMAGE_RE.fullmatch(str(evidence.get("image") or "")):
        errors.append("image must be pinned by a 64-hex sha256 digest")
    if evidence.get("network_mode") != "model-endpoint-only":
        errors.append("network_mode must be 'model-endpoint-only'")
    runtime_source_required = evidence.get("runtime_source_mounted") is True
    if runtime_source_required and not _SHA256_RE.fullmatch(
        str(evidence.get("runtime_source_sha256") or "")
    ):
        errors.append("runtime source digest is missing or invalid")
    if not _SHA256_RE.fullmatch(str(evidence.get("network_policy_sha256") or "")):
        errors.append("network policy digest is missing or invalid")
    provider_identity_sha256 = str(evidence.get("provider_identity_sha256") or "")
    if not _SHA256_RE.fullmatch(provider_identity_sha256):
        errors.append("provider identity digest is missing or invalid")
    if (
        _runtime_family(str(evidence.get("runtime") or ""), str(evidence.get("runtime_path") or ""))
        not in _ALLOWED_RUNTIME_NAMES
    ):
        errors.append("runtime must be verified as podman or docker")

    scanner_cwd = str(evidence.get("scanner_cwd") or "")
    try:
        cwd = PurePosixPath(scanner_cwd)
    except (TypeError, ValueError):
        cwd = PurePosixPath(".")
    if not scanner_cwd or not cwd.is_absolute():
        errors.append("scanner_cwd must be an absolute container path")

    raw_mounts = evidence.get("mounts")
    mounts = raw_mounts if isinstance(raw_mounts, list) else []
    if not mounts:
        errors.append("mount evidence is missing")
    scan_mount_found = False
    found_purposes: set[str] = set()
    mount_sources: list[Path] = []
    checkout = Path(repository_checkout).resolve() if repository_checkout else None
    protected_truth = [Path(path).resolve() for path in truth_paths]
    for index, raw in enumerate(mounts):
        if not isinstance(raw, Mapping):
            errors.append(f"mounts[{index}] is not an object")
            continue
        source_text = str(raw.get("source") or "")
        destination_text = str(raw.get("destination") or "")
        purpose = str(raw.get("purpose") or "")
        if purpose not in {"scan_input", "artifact_output", "cache", "runtime_source"}:
            errors.append(f"mounts[{index}] has invalid purpose")
        if not source_text or not destination_text:
            errors.append(f"mounts[{index}] has no source or destination")
            continue
        source = Path(source_text).resolve()
        mount_sources.append(source)
        found_purposes.add(purpose)
        try:
            destination = PurePosixPath(destination_text)
        except (TypeError, ValueError):
            errors.append(f"mounts[{index}] destination is invalid")
            continue
        if checkout and (
            source == checkout or checkout.is_relative_to(source) or source.is_relative_to(checkout)
        ):
            errors.append(f"mounts[{index}] contains the repository checkout")
        if purpose == "scan_input" and (cwd == destination or destination in cwd.parents):
            scan_mount_found = True
            if raw.get("read_only") is not True:
                errors.append("scan_input mount must be read-only")
        elif purpose in {"artifact_output", "cache"} and raw.get("read_only") is True:
            errors.append(f"{purpose} mount must be writable")
        elif purpose == "runtime_source":
            if destination_text != "/zscope-runtime/zscope":
                errors.append("runtime_source mount destination is invalid")
            if raw.get("read_only") is not True:
                errors.append("runtime_source mount must be read-only")
        for truth in protected_truth:
            if truth == source or truth.is_relative_to(source):
                errors.append(f"mounts[{index}] contains benchmark truth")
    if not scan_mount_found:
        errors.append("scanner_cwd is not within the sealed scan_input mount")
    for purpose in ("scan_input", "artifact_output", "cache"):
        if purpose not in found_purposes:
            errors.append(f"{purpose} mount evidence is missing")
    if runtime_source_required and "runtime_source" not in found_purposes:
        errors.append("runtime_source mount evidence is missing")
    if any(
        left == right or left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(mount_sources)
        for right in mount_sources[index + 1 :]
    ):
        errors.append("isolation mount sources are not disjoint")

    phases = evidence.get("phase_executions")
    if not isinstance(phases, list) or not phases:
        errors.append("actual phase execution evidence is missing")
    else:
        required = {str(value) for value in evidence.get("required_phases") or [] if str(value)}
        observed: set[str] = set()
        for index, raw in enumerate(phases):
            if not isinstance(raw, Mapping):
                errors.append(f"phase_executions[{index}] is not an object")
                continue
            observed.add(str(raw.get("phase") or ""))
            for field in (
                "inspect_verified",
                "security_verified",
                "network_peers_verified",
                "network_contract_verified",
                "proxy_verified",
                "proxy_credential_metadata_safe",
                "scanner_labels_verified",
                "scanner_provider_environment_verified",
                "cancellation_cleanup_guard_verified",
                "image_verified",
            ):
                if raw.get(field) is not True:
                    errors.append(f"phase_executions[{index}].{field} must be true")
            for field in ("stdout_persisted", "stderr_persisted"):
                if raw.get(field) is not False:
                    errors.append(f"phase_executions[{index}].{field} must be false")
            if str(raw.get("provider_identity_sha256") or "") != provider_identity_sha256:
                errors.append(f"phase_executions[{index}] provider identity does not match")
            provider_keys = raw.get("scanner_provider_environment_keys")
            if not isinstance(provider_keys, list) or any(
                not isinstance(key, str) or not key for key in provider_keys
            ):
                errors.append(f"phase_executions[{index}] provider environment keys are invalid")
            elif raw.get("phase") == "scan" and "Z_SCOPE_API_KEY" not in provider_keys:
                errors.append(f"phase_executions[{index}] scan provider environment key is missing")
            if not require_release_capable and (
                raw.get("phase") != "preflight" or provider_keys != []
            ):
                errors.append(
                    f"phase_executions[{index}] bootstrap phase must be credential-free preflight"
                )
            p6_values = (
                raw.get("p6_workflow_run_id"),
                raw.get("p6_workflow_run_attempt"),
                raw.get("p6_attempt_id"),
                raw.get("p6_repository"),
                raw.get("p6_concurrency_group"),
                raw.get("p6_phase"),
            )
            if any(value is not None and value != "" and value != 0 for value in p6_values):
                run_id = str(raw.get("p6_workflow_run_id") or "")
                run_attempt = raw.get("p6_workflow_run_attempt")
                attempt_id = str(raw.get("p6_attempt_id") or "")
                if (
                    raw.get("p6_cleanup_scope_verified") is not True
                    or _P6_POSITIVE_INTEGER_RE.fullmatch(run_id) is None
                    or isinstance(run_attempt, bool)
                    or not isinstance(run_attempt, int)
                    or run_attempt < 1
                    or attempt_id != f"p6-{run_id}-{run_attempt}"
                    or _P6_REPOSITORY_RE.fullmatch(str(raw.get("p6_repository") or "")) is None
                    or raw.get("p6_concurrency_group") != P6_OCI_CONCURRENCY_GROUP
                    or raw.get("p6_phase") != _safe_phase_name(str(raw.get("phase") or ""))
                ):
                    errors.append(f"phase_executions[{index}] P6 cleanup scope is invalid")
            if int(raw.get("unexpected_mount_count") or 0) != 0:
                errors.append(f"phase_executions[{index}] has unexpected mounts")
            if not _SHA256_RE.fullmatch(str(raw.get("container_inspect_sha256") or "")):
                errors.append(f"phase_executions[{index}] lacks container inspect digest")
            if not _SHA256_RE.fullmatch(str(raw.get("network_inspect_sha256") or "")):
                errors.append(f"phase_executions[{index}] lacks network inspect digest")
            if not _SHA256_RE.fullmatch(str(raw.get("proxy_inspect_sha256") or "")):
                errors.append(f"phase_executions[{index}] lacks proxy inspect digest")
        if not required.issubset(observed):
            errors.append("required OCI phases are missing from execution evidence")
    return list(dict.fromkeys(errors))
