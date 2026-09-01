"""Reproducible, credential-free local runtime support for the P6 pilot.

This module owns only OCI image provenance and the transparent model-endpoint
network boundary.  It never reads the P6 API-key file and never accepts a
credential value in argv.  The scanner still receives its bearer exclusively
through :class:`~zscope.benchmarking.isolation.RootlessOciExecutor`.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence, cast
from urllib.parse import urlsplit

from zscope.benchmarking.isolation import (
    P6_BOOTSTRAP_PROXY_ATTESTATION_SCHEMA_VERSION,
    BenchmarkIsolationError,
    OciNetworkPolicy,
)
from zscope.benchmarking.p6_protocol import (
    EXPECTED_PROXY_ATTESTATION_SCHEMA_VERSION,
    canonical_sha256,
    load_json_bytes_strict,
    load_json_strict,
    read_regular_file_once,
    validate_expected_proxy_attestation,
    validate_proxy_provision,
    validate_toolchain_provenance_files,
)
from zscope.benchmarking.provider_runtime import ProviderRuntimeContract


RUNTIME_LOCK_SCHEMA_VERSION = "zscope.p6-runtime-lock.v1"
IMAGE_PROVENANCE_SCHEMA_VERSION = "zscope.p6-local-image-provenance.v1"
PROXY_PROVISION_SCHEMA_VERSION = "zscope.p6-local-proxy-provision.v2"
BASE_IMAGE_DIGEST = "sha256:de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a"
BASE_IMAGE_REF = f"docker.io/library/python@{BASE_IMAGE_DIGEST}"
NETWORK_LABEL_MODE = "io.zscope.network-policy"
NETWORK_LABEL_SHA = "io.zscope.network-policy-sha256"
PROXY_LABEL_ROLE = "io.zscope.role"
PROXY_LABEL_RELAY = "io.zscope.relay-sha256"
PROXY_LABEL_RELAY_PROJECTION = "io.zscope.relay-projection-sha256"
PROXY_LABEL_UPSTREAMS = "io.zscope.upstreams-sha256"
EGRESS_LABEL_ROLE = "io.zscope.role"
IMAGE_LABEL_BASE_DIGEST = "org.opencontainers.image.base.digest"
IMAGE_LABEL_REVISION = "org.opencontainers.image.revision"
IMAGE_LABEL_LOCK = "io.zscope.p6-runtime-lock-sha256"
IMAGE_LABEL_CONTAINERFILE = "io.zscope.p6-containerfile-sha256"
P6_REQUIRED_TOOLS = (
    "python3",
    "cmake",
    "gcc",
    "clang",
    "clangd",
    "gclang",
    "get-bc",
    "llvm-link",
    "llvm-nm",
    "wpa",
    "saber",
    "cc",
)
P6_VERSIONED_TOOLS = ("python3", "cmake", "gcc", "clang", "clangd")

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_OCI_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
_CREDENTIAL_MARKERS = (
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "ACCESSKEY",
    "GPG_KEY",
    "AUTH",
    "AUTHORIZATION",
    "BEARER",
    "CERTIFICATE",
    "CONNECTION_STRING",
    "CREDENTIAL",
    "COOKIE",
    "JWT",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "SECRET",
    "SECRETKEY",
    "SESSION_KEY",
    "SIGNING_KEY",
    "TOKEN",
)
_CREDENTIAL_KEYS = frozenset(
    {
        "GH_PAT",
        "GITHUB_PAT",
        "KUBECONFIG",
        "NETRC",
        "AWS_ACCESS_KEY_ID",
        "AWS_CONFIG_FILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_PROFILE",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AZURE_CLIENT_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "DOCKER_CONFIG",
        "DOCKER_AUTH_CONFIG",
        "GIT_ASKPASS",
        "OCI_CLI_CONFIG_FILE",
        "OCI_CLI_FINGERPRINT",
        "OCI_CLI_PROFILE",
        "OCI_CLI_TENANCY",
        "OCI_CLI_USER",
        "SSH_ASKPASS",
        "NPM_TOKEN",
        "PYPI_TOKEN",
    }
)
_PROVIDER_AUTH_PREFIXES = (
    "ALIBABA",
    "ALIYUN",
    "ANTHROPIC",
    "ARK",
    "AWS",
    "AZURE",
    "BAIDU",
    "BEDROCK",
    "CLOUDFLARE",
    "COHERE",
    "DASHSCOPE",
    "DEEPSEEK",
    "GCP",
    "GOOGLE",
    "GROQ",
    "HUAWEI",
    "HWC",
    "MINIMAX",
    "MISTRAL",
    "MOONSHOT",
    "OCI",
    "OPENAI",
    "QIANFAN",
    "TENCENT",
    "VERTEX",
    "VOLC",
    "ZHIPU",
)
_ANSWER_ENVIRONMENT_MARKERS = ("GROUND_TRUTH", "BENCHMARK_TRUTH")
_MINIMAL_CONTEXT_PATHS = (
    "Containerfile",
    "containers/p6/runtime-lock.json",
    "containers/p6/verify_toolchain.py",
    "requirements/release/py313.txt",
)
_PROXY_RELAY_DESTINATION = "/opt/zscope/p6_tcp_relay.py"
_PROXY_TMPFS_OPTIONS = frozenset({"rw", "noexec", "nosuid", "nodev", "size=16m"})
_IMAGE_PYTHON = "/usr/local/bin/python3"
_IMAGE_EXPECTED_ENTRYPOINT: None = None
_IMAGE_EXPECTED_COMMAND = ["python3", "--version"]
_IMAGE_ROOTFS_PROBE_SCHEMA_VERSION = "zscope.p6-image-rootfs-probe.v1"
_IMAGE_ROOTFS_PATHS = (
    "/opt/zscope/requirements/py313.txt",
    "/opt/zscope/verify_toolchain.py",
)
_IMAGE_ROOTFS_PROBE_CODE = r"""
import hashlib
import json
import os
import stat

paths = (
    "/opt/zscope/requirements/py313.txt",
    "/opt/zscope/verify_toolchain.py",
)
files = {}
for path in paths:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(91)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    projected = os.stat(path, follow_symlinks=False)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size)
    if identity(before) != identity(after) or identity(after) != identity(projected):
        raise SystemExit(92)
    content = b"".join(chunks)
    if len(content) != after.st_size:
        raise SystemExit(93)
    files[path] = hashlib.sha256(content).hexdigest()

customizations = []
for root in ("/usr/local/lib/python3.13", "/usr/local/lib/python3.13/site-packages"):
    if not os.path.isdir(root):
        continue
    for current, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            if name in {"sitecustomize", "usercustomize"}:
                customizations.append(os.path.join(current, name))
        directories[:] = [
            name for name in directories
            if not os.path.islink(os.path.join(current, name))
        ]
        for name in names:
            if any(
                name == stem or name.startswith(stem + ".")
                for stem in ("sitecustomize", "usercustomize")
            ):
                customizations.append(os.path.join(current, name))

print(json.dumps({
    "schema_version": "zscope.p6-image-rootfs-probe.v1",
    "files": files,
    "python_customization_paths": sorted(set(customizations)),
}, sort_keys=True, separators=(",", ":")))
""".strip()
_RELAY_LIVE_PROBE_SCHEMA_VERSION = "zscope.p6-relay-live-probe.v1"
_RELAY_LIVE_PROBE_CODE = r"""
import hashlib
import json
import os
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit(81)
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
projected = os.stat(path, follow_symlinks=False)
identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size)
if identity(before) != identity(after) or identity(after) != identity(projected):
    raise SystemExit(82)
content = b"".join(chunks)
if len(content) != after.st_size:
    raise SystemExit(83)
print(json.dumps({
    "schema_version": "zscope.p6-relay-live-probe.v1",
    "destination": path,
    "device": after.st_dev,
    "inode": after.st_ino,
    "mode": stat.S_IMODE(after.st_mode),
    "sha256": hashlib.sha256(content).hexdigest(),
    "size": after.st_size,
}, sort_keys=True, separators=(",", ":")))
""".strip()
_PODMAN_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_PODMAN_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "LANG",
        "PATH",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    }
)

ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]
AddressResolver = Callable[[str, int], Sequence[tuple[str, int]]]


class P6LocalRuntimeError(RuntimeError):
    """A local P6 runtime identity or isolation boundary failed closed."""


def _normalized_environment_key(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(value or "").upper()).strip("_")


def _credential_like_environment_key(value: Any) -> bool:
    key = _normalized_environment_key(value)
    if not key:
        return True
    if key in _CREDENTIAL_KEYS or key.endswith("_PAT"):
        return True
    if any(marker in key for marker in _CREDENTIAL_MARKERS):
        return True
    return key.startswith(_PROVIDER_AUTH_PREFIXES) and any(
        marker in key for marker in ("KEY", "SECRET", "TOKEN", "AUTH", "CREDENTIAL", "CERT")
    )


def _sensitive_environment_key(value: Any) -> bool:
    key = _normalized_environment_key(value)
    return _credential_like_environment_key(key) or any(
        marker in key for marker in _ANSWER_ENVIRONMENT_MARKERS
    )


def _validate_private_directory(path: Path, *, empty: bool, name: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise P6LocalRuntimeError(f"{name} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise P6LocalRuntimeError(f"{name} must be a directory")
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise P6LocalRuntimeError(f"{name} must be private")
    uid = _current_uid()
    if uid is not None and metadata.st_uid != uid:
        raise P6LocalRuntimeError(f"{name} ownership is invalid")
    if empty:
        try:
            if any(path.iterdir()):
                raise P6LocalRuntimeError(f"{name} must be empty")
        except OSError as exc:
            raise P6LocalRuntimeError(f"{name} is unavailable") from exc


def _current_uid() -> int | None:
    getter = getattr(os, "getuid", None)
    return int(getter()) if callable(getter) else None


def _trusted_account_home() -> Path:
    if os.name != "posix":
        # This branch is used only by mocked unit tests.  Real P6 OCI execution
        # is Linux-only and resolves the account home without consulting env.
        return Path(tempfile.gettempdir()).resolve()
    try:
        uid = _current_uid()
        if uid is None:
            raise P6LocalRuntimeError("P6 OCI account identity is unavailable")
        pwd_module = importlib.import_module("pwd")
        home = Path(getattr(pwd_module, "getpwuid")(uid).pw_dir)
        metadata = home.lstat()
    except (KeyError, OSError, RuntimeError) as exc:
        raise P6LocalRuntimeError("P6 OCI account home is unavailable") from exc
    if (
        not home.is_absolute()
        or home.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
    ):
        raise P6LocalRuntimeError("P6 OCI account home is invalid")
    return home.resolve(strict=True)


def _trusted_runtime_directory(context: Path) -> Path:
    if os.name != "posix":
        runtime = context / "xdg-runtime"
        runtime.mkdir(mode=0o700)
        _validate_private_directory(runtime, empty=True, name="P6 OCI XDG runtime")
        return runtime
    uid = _current_uid()
    if uid is None:
        raise P6LocalRuntimeError("P6 OCI account identity is unavailable")
    candidate = Path("/run/user") / str(uid)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise P6LocalRuntimeError("P6 OCI XDG runtime is unavailable") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_mode & 0o077
    ):
        raise P6LocalRuntimeError("P6 OCI XDG runtime is invalid")
    return candidate.resolve(strict=True)


@contextmanager
def _private_podman_environment() -> Iterator[dict[str, str]]:
    """Yield a closed, credential-free Podman environment.

    The only persistent paths are derived from the authenticated OS account,
    never caller-controlled environment variables.  Config, cache and temp
    roots are fresh private directories so Podman cannot consume injected
    containers.conf, auth.json, proxy variables, dynamic-loader variables, or
    helper binaries from the invoking process.
    """

    with tempfile.TemporaryDirectory(prefix="zscope-p6-oci-") as temporary:
        context = Path(temporary)
        os.chmod(context, 0o700)
        _validate_private_directory(context, empty=True, name="P6 OCI runtime context")
        config = context / "config"
        cache = context / "cache"
        temp = context / "tmp"
        for path in (config, cache, temp):
            path.mkdir(mode=0o700)
            _validate_private_directory(path, empty=True, name="P6 OCI private context")
        home = _trusted_account_home()
        environment = {
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "PATH": _PODMAN_PATH,
            "TMPDIR": str(temp),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config),
            # Podman's persistent rootless image store is account-derived.  It
            # is not accepted from XDG_DATA_HOME in the caller environment.
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_RUNTIME_DIR": str(_trusted_runtime_directory(context)),
        }
        if set(environment) != _PODMAN_ENVIRONMENT_KEYS:
            raise P6LocalRuntimeError("P6 OCI subprocess environment is invalid")
        yield environment


def _strict_object(path: Path, *, name: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise P6LocalRuntimeError(f"{name} must be a regular file")
    try:
        value = load_json_strict(path)
    except Exception as exc:
        raise P6LocalRuntimeError(f"{name} is invalid") from exc
    if not isinstance(value, dict):
        raise P6LocalRuntimeError(f"{name} must contain one object")
    return value


@dataclass(frozen=True)
class _FileSnapshot:
    content: bytes
    device: int
    inode: int
    size: int
    mode: int
    uid: int

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def projection_sha256(self) -> str:
        return str(
            canonical_sha256(
                {
                    "device": self.device,
                    "inode": self.inode,
                    "mode": stat.S_IMODE(self.mode),
                    "sha256": self.sha256,
                    "size": self.size,
                    "uid": self.uid,
                }
            )
        )


def _snapshot_regular_file(path: Path, *, name: str) -> _FileSnapshot:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise P6LocalRuntimeError(f"{name} must be a regular file") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise P6LocalRuntimeError(f"{name} must be a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        try:
            projected = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise P6LocalRuntimeError(f"{name} changed while being captured") from exc
        identity_before: tuple[int, ...] = (
            before.st_dev,
            before.st_ino,
            before.st_size,
        )
        identity_after: tuple[int, ...] = (
            after.st_dev,
            after.st_ino,
            after.st_size,
        )
        path_identity: tuple[int, ...] = (
            projected.st_dev,
            projected.st_ino,
            projected.st_size,
        )
        if os.name == "posix":
            identity_before += (before.st_mtime_ns, before.st_ctime_ns, before.st_mode)
            identity_after += (after.st_mtime_ns, after.st_ctime_ns, after.st_mode)
            path_identity += (
                projected.st_mtime_ns,
                projected.st_ctime_ns,
                projected.st_mode,
            )
        content = b"".join(chunks)
        if (
            identity_before != identity_after
            or identity_after != path_identity
            or len(content) != after.st_size
        ):
            raise P6LocalRuntimeError(f"{name} changed while being captured")
        return _FileSnapshot(
            content=content,
            device=int(after.st_dev),
            inode=int(after.st_ino),
            size=int(after.st_size),
            mode=int(after.st_mode),
            uid=int(after.st_uid),
        )
    finally:
        os.close(descriptor)


def _relay_projection_sha256(snapshot: _FileSnapshot) -> str:
    return str(
        canonical_sha256(
            {
                "destination": _PROXY_RELAY_DESTINATION,
                "device": snapshot.device,
                "inode": snapshot.inode,
                "mode": stat.S_IMODE(snapshot.mode),
                "sha256": snapshot.sha256,
                "size": snapshot.size,
            }
        )
    )


def _file_sha256(path: Path) -> str:
    return _snapshot_regular_file(path, name="runtime source artifact").sha256


def _atomic_write_new_json(output: Path, payload: Mapping[str, Any], *, name: str) -> None:
    body = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        parent_metadata = output.parent.lstat()
        parent_resolved = output.parent.resolve(strict=True)
    except OSError as exc:
        raise P6LocalRuntimeError(f"{name} output directory is unavailable") from exc
    if output.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        raise P6LocalRuntimeError(f"{name} output directory is invalid")
    temporary = parent_resolved / f".{output.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    linked = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        offset = 0
        while offset < len(body):
            offset += os.write(descriptor, body[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, output, follow_symlinks=False)
        linked = True
        final = _snapshot_regular_file(output, name=name)
        if final.content != body:
            raise P6LocalRuntimeError(f"{name} changed while being published")
    except (OSError, P6LocalRuntimeError) as exc:
        if linked:
            try:
                output.unlink()
            except OSError:
                pass
        if isinstance(exc, P6LocalRuntimeError):
            raise
        raise P6LocalRuntimeError(f"{name} could not be published atomically") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _expect_sha(value: Any, *, name: str, prefixed: bool = False) -> str:
    text = str(value or "")
    matcher = _DIGEST_RE if prefixed else _SHA256_RE
    if matcher.fullmatch(text) is None:
        raise P6LocalRuntimeError(f"{name} is invalid")
    return text


def validate_runtime_lock(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version",
        "platform",
        "base_image",
        "archives",
        "gllvm",
        "debian_packages",
        "python_requirements",
        "required_tools",
    }
    if set(value) != expected or value.get("schema_version") != RUNTIME_LOCK_SCHEMA_VERSION:
        raise P6LocalRuntimeError("P6 runtime lock fields are invalid")
    if value.get("platform") != "linux/amd64":
        raise P6LocalRuntimeError("P6 runtime lock platform is invalid")
    base = value.get("base_image")
    if (
        not isinstance(base, Mapping)
        or set(base) != {"ref", "digest", "python_version"}
        or base.get("ref") != BASE_IMAGE_REF
        or base.get("digest") != BASE_IMAGE_DIGEST
        or base.get("python_version") != "3.13.15"
    ):
        raise P6LocalRuntimeError("P6 base image lock is invalid")
    archives = value.get("archives")
    if not isinstance(archives, list) or len(archives) != 2:
        raise P6LocalRuntimeError("P6 archive lock is invalid")
    archive_names: set[str] = set()
    for row in archives:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"name", "url", "sha256", "format"}
            or row.get("format") not in {"tar.gz", "zip"}
            or not str(row.get("url") or "").startswith("https://github.com/SVF-tools/SVF/")
        ):
            raise P6LocalRuntimeError("P6 archive row is invalid")
        name = str(row.get("name") or "")
        if not name or name in archive_names:
            raise P6LocalRuntimeError("P6 archive names are invalid")
        archive_names.add(name)
        _expect_sha(row.get("sha256"), name="P6 archive SHA-256")
    gllvm = value.get("gllvm")
    if (
        not isinstance(gllvm, Mapping)
        or set(gllvm) != {"module", "version", "commands"}
        or gllvm.get("module") != "github.com/SRI-CSL/gllvm"
        or gllvm.get("version") != "v1.3.1"
        or gllvm.get("commands") != ["gclang", "gclang++", "get-bc"]
    ):
        raise P6LocalRuntimeError("P6 gllvm lock is invalid")
    packages = value.get("debian_packages")
    tools = value.get("required_tools")
    if (
        not isinstance(packages, list)
        or packages != sorted(set(str(item) for item in packages))
        or not isinstance(tools, list)
        or len(tools) != len(set(str(item) for item in tools))
        or tuple(str(item) for item in tools) != P6_REQUIRED_TOOLS
        or value.get("python_requirements") != "requirements/release/py313.txt"
    ):
        raise P6LocalRuntimeError("P6 package or tool contract is invalid")
    return cast(dict[str, Any], json.loads(json.dumps(dict(value))))


def load_runtime_lock(path: Path) -> tuple[dict[str, Any], str]:
    value = validate_runtime_lock(_strict_object(path, name="P6 runtime lock"))
    return value, _file_sha256(path)


def _validate_toolchain_probe(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "required_tools",
        "paths",
        "versions",
        "missing_shared_libraries",
        "passed",
    }:
        raise P6LocalRuntimeError("P6 toolchain probe fields are invalid")
    paths = value.get("paths")
    versions = value.get("versions")
    missing = value.get("missing_shared_libraries")
    if (
        value.get("schema_version") != "zscope.p6-toolchain-probe.v1"
        or tuple(value.get("required_tools") or ()) != P6_REQUIRED_TOOLS
        or not isinstance(paths, Mapping)
        or set(paths) != set(P6_REQUIRED_TOOLS)
        or any(
            not isinstance(paths[name], str)
            or not paths[name].startswith("/")
            or "\x00" in paths[name]
            for name in P6_REQUIRED_TOOLS
        )
        or not isinstance(versions, Mapping)
        or set(versions) != set(P6_VERSIONED_TOOLS)
        or any(
            not isinstance(versions[name], str)
            or not versions[name].strip()
            or len(versions[name]) > 256
            for name in P6_VERSIONED_TOOLS
        )
        or not isinstance(missing, Mapping)
        or set(missing) != {"wpa", "saber"}
        or any(missing[name] != [] for name in ("wpa", "saber"))
        or value.get("passed") is not True
    ):
        raise P6LocalRuntimeError("P6 toolchain probe is invalid")
    return cast(dict[str, Any], json.loads(json.dumps(dict(value))))


def _validate_image_rootfs_probe(
    value: Any, *, requirements_sha256: str, verifier_sha256: str
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "files",
        "python_customization_paths",
    }:
        raise P6LocalRuntimeError("P6 image rootfs probe fields are invalid")
    files = value.get("files")
    if (
        value.get("schema_version") != _IMAGE_ROOTFS_PROBE_SCHEMA_VERSION
        or not isinstance(files, Mapping)
        or set(files) != set(_IMAGE_ROOTFS_PATHS)
        or files.get("/opt/zscope/requirements/py313.txt") != requirements_sha256
        or files.get("/opt/zscope/verify_toolchain.py") != verifier_sha256
        or value.get("python_customization_paths") != []
    ):
        raise P6LocalRuntimeError("P6 image rootfs identity is invalid")


def validate_image_provenance(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version",
        "git_revision",
        "platform",
        "base_image_ref",
        "base_image_digest",
        "runtime_lock_sha256",
        "containerfile_sha256",
        "python_requirements_sha256",
        "image_ref",
        "image_digest",
        "image_id",
        "toolchain_probe",
        "credential_material_present",
        "formal_evidence",
        "release_eligible",
        "content_sha256",
    }
    if set(value) != expected:
        raise P6LocalRuntimeError("P6 image provenance fields are invalid")
    unsigned = dict(value)
    supplied = unsigned.pop("content_sha256", None)
    if (
        value.get("schema_version") != IMAGE_PROVENANCE_SCHEMA_VERSION
        or value.get("platform") != "linux/amd64"
        or value.get("base_image_ref") != BASE_IMAGE_REF
        or value.get("base_image_digest") != BASE_IMAGE_DIGEST
        or _GIT_RE.fullmatch(str(value.get("git_revision") or "")) is None
        or _SHA256_RE.fullmatch(str(value.get("runtime_lock_sha256") or "")) is None
        or _SHA256_RE.fullmatch(str(value.get("containerfile_sha256") or "")) is None
        or _SHA256_RE.fullmatch(str(value.get("python_requirements_sha256") or "")) is None
        or _DIGEST_RE.fullmatch(str(value.get("image_digest") or "")) is None
        or not str(value.get("image_ref") or "").endswith(
            "@" + str(value.get("image_digest") or "")
        )
        or re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", str(value.get("image_id") or "")) is None
        or value.get("credential_material_present") is not False
        or value.get("formal_evidence") is not False
        or value.get("release_eligible") is not False
        or supplied != canonical_sha256(unsigned)
    ):
        raise P6LocalRuntimeError("P6 image provenance is invalid")
    _validate_toolchain_probe(value.get("toolchain_probe"))
    return cast(dict[str, Any], json.loads(json.dumps(dict(value))))


def load_image_provenance(path: Path) -> dict[str, Any]:
    return validate_image_provenance(_strict_object(path, name="P6 image provenance"))


def _json_result(result: subprocess.CompletedProcess[str], *, name: str) -> Any:
    if result.returncode != 0:
        raise P6LocalRuntimeError(f"{name} failed")
    try:
        value = json.loads(str(result.stdout or ""))
    except json.JSONDecodeError as exc:
        raise P6LocalRuntimeError(f"{name} did not return JSON") from exc
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    return value


def _invoke(
    runner: ProcessRunner,
    argv: Sequence[str],
    *,
    name: str,
    environment: Mapping[str, str],
    expect_json: bool = False,
    stdin_bytes: bytes | None = None,
) -> Any:
    if set(environment) != _PODMAN_ENVIRONMENT_KEYS:
        raise P6LocalRuntimeError("P6 OCI subprocess environment is invalid")
    if stdin_bytes is not None and expect_json:
        raise P6LocalRuntimeError(f"{name} stdin transport is invalid")
    kwargs: dict[str, Any] = {
        "check": False,
        "text": stdin_bytes is None,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": dict(environment),
    }
    if stdin_bytes is not None:
        kwargs["input"] = stdin_bytes
    result = runner([str(item) for item in argv], **kwargs)
    if expect_json:
        return _json_result(result, name=name)
    if result.returncode != 0:
        raise P6LocalRuntimeError(f"{name} failed")
    return result


def _validate_live_relay_projection(
    *,
    runtime: str,
    proxy_container_id: str,
    expected: _FileSnapshot,
    process_runner: ProcessRunner,
    environment: Mapping[str, str],
) -> str:
    """Bind the receipt to the inode and bytes actually mounted in the OCI.

    ``podman inspect`` reports a bind source *pathname*, not the inode Podman
    opened.  A swap/restore race can therefore make that pathname look clean
    while the container retains an attacker inode.  Probe the destination by
    exact container ID with the immutable image interpreter, compare every
    bind-relevant stat field and the content digest, then hash that live
    projection for the receipt.
    """

    if re.fullmatch(r"[0-9a-f]{64}", proxy_container_id) is None:
        raise P6LocalRuntimeError("P6 proxy container identity is missing or truncated")
    value = _invoke(
        process_runner,
        [
            runtime,
            "exec",
            proxy_container_id,
            _IMAGE_PYTHON,
            "-I",
            "-S",
            "-c",
            _RELAY_LIVE_PROBE_CODE,
            _PROXY_RELAY_DESTINATION,
        ],
        name="P6 proxy live relay probe",
        environment=environment,
        expect_json=True,
    )
    expected_fields = {
        "schema_version",
        "destination",
        "device",
        "inode",
        "mode",
        "sha256",
        "size",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected_fields
        or value.get("schema_version") != _RELAY_LIVE_PROBE_SCHEMA_VERSION
        or value.get("destination") != _PROXY_RELAY_DESTINATION
        or value.get("device") != expected.device
        or value.get("inode") != expected.inode
        or value.get("mode") != stat.S_IMODE(expected.mode)
        or value.get("sha256") != expected.sha256
        or value.get("size") != expected.size
    ):
        raise P6LocalRuntimeError("P6 proxy live relay projection is invalid")
    unsigned = dict(value)
    unsigned.pop("schema_version")
    projection = str(canonical_sha256(unsigned))
    if projection != _relay_projection_sha256(expected):
        raise P6LocalRuntimeError("P6 proxy live relay projection is invalid")
    return projection


def _source_file_at_exact_context_path(
    supplied: Path,
    *,
    context: Path,
    relative: str,
    name: str,
) -> Path:
    expected = context.joinpath(*relative.split("/"))
    try:
        supplied_resolved = supplied.resolve(strict=True)
        expected_resolved = expected.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise P6LocalRuntimeError(f"{name} is unavailable") from exc
    if supplied.is_symlink() or supplied_resolved != expected_resolved:
        raise P6LocalRuntimeError(f"{name} is outside its exact build-context path")
    cursor = expected
    while cursor != context:
        try:
            mode = cursor.lstat().st_mode
        except OSError as exc:
            raise P6LocalRuntimeError(f"{name} is unavailable") from exc
        if stat.S_ISLNK(mode):
            raise P6LocalRuntimeError(f"{name} build-context path contains a symlink")
        cursor = cursor.parent
    if not stat.S_ISREG(expected.lstat().st_mode):
        raise P6LocalRuntimeError(f"{name} must be a regular file")
    return expected_resolved


def _minimal_build_context_archive(snapshots: Mapping[str, bytes]) -> bytes:
    """Return the complete minimal build context as one immutable stdin blob."""

    if set(snapshots) != set(_MINIMAL_CONTEXT_PATHS) or any(
        not isinstance(content, bytes) for content in snapshots.values()
    ):
        raise P6LocalRuntimeError("P6 minimal build context layout is invalid")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for relative in sorted(snapshots):
            content = snapshots[relative]
            member = tarfile.TarInfo(relative)
            member.mode = 0o444
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    payload = buffer.getvalue()

    # Validate the exact bytes that will be handed to Podman.  The builder
    # consumes this immutable object from stdin, so there is no context
    # pathname for an attacker to swap and later restore.
    observed: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive.getmembers():
                if (
                    not member.isreg()
                    or member.name not in snapshots
                    or member.name in observed
                    or member.mode != 0o444
                    or member.mtime != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                ):
                    raise P6LocalRuntimeError("P6 minimal build archive is invalid")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise P6LocalRuntimeError("P6 minimal build archive is invalid")
                observed[member.name] = extracted.read()
    except (OSError, tarfile.TarError) as exc:
        raise P6LocalRuntimeError("P6 minimal build archive is invalid") from exc
    if observed != dict(snapshots):
        raise P6LocalRuntimeError("P6 minimal build archive is invalid")
    return payload


def build_toolchain_image(
    *,
    runtime: str,
    repository: str,
    git_revision: str,
    lock_path: Path,
    containerfile: Path,
    context: Path,
    output: Path,
    process_runner: ProcessRunner = subprocess.run,
) -> dict[str, Any]:
    """Build and bind one local immutable image without reading credentials."""

    with _private_podman_environment() as environment:
        return _build_toolchain_image(
            runtime=runtime,
            repository=repository,
            git_revision=git_revision,
            lock_path=lock_path,
            containerfile=containerfile,
            context=context,
            output=output,
            process_runner=process_runner,
            subprocess_environment=environment,
        )


def _build_toolchain_image(
    *,
    runtime: str,
    repository: str,
    git_revision: str,
    lock_path: Path,
    containerfile: Path,
    context: Path,
    output: Path,
    subprocess_environment: Mapping[str, str],
    process_runner: ProcessRunner = subprocess.run,
) -> dict[str, Any]:
    if runtime != "podman" or _SAFE_OCI_NAME_RE.fullmatch(repository) is None:
        raise P6LocalRuntimeError("P6 local image runtime or repository is invalid")
    if _GIT_RE.fullmatch(git_revision) is None:
        raise P6LocalRuntimeError("P6 local image Git revision is invalid")
    if context.is_symlink() or not context.is_dir():
        raise P6LocalRuntimeError("P6 image build context must be a regular directory")
    try:
        source_context = context.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise P6LocalRuntimeError("P6 image build context is unavailable") from exc
    source_lock = _source_file_at_exact_context_path(
        lock_path,
        context=source_context,
        relative="containers/p6/runtime-lock.json",
        name="P6 runtime lock",
    )
    source_containerfile = _source_file_at_exact_context_path(
        containerfile,
        context=source_context,
        relative="containers/p6/Containerfile",
        name="P6 Containerfile",
    )
    source_requirements = _source_file_at_exact_context_path(
        source_context / "requirements/release/py313.txt",
        context=source_context,
        relative="requirements/release/py313.txt",
        name="P6 Python requirements",
    )
    source_verifier = _source_file_at_exact_context_path(
        source_context / "containers/p6/verify_toolchain.py",
        context=source_context,
        relative="containers/p6/verify_toolchain.py",
        name="P6 toolchain verifier",
    )
    lock_snapshot = _snapshot_regular_file(source_lock, name="P6 runtime lock")
    containerfile_snapshot = _snapshot_regular_file(source_containerfile, name="P6 Containerfile")
    verifier_snapshot = _snapshot_regular_file(source_verifier, name="P6 toolchain verifier")
    requirements_snapshot = _snapshot_regular_file(
        source_requirements, name="P6 Python requirements"
    )
    lock_value = load_json_bytes_strict(lock_snapshot.content, name="P6 runtime lock")
    if not isinstance(lock_value, Mapping):
        raise P6LocalRuntimeError("P6 runtime lock must contain one object")
    lock = validate_runtime_lock(lock_value)
    lock_sha = lock_snapshot.sha256
    if lock["python_requirements"] != "requirements/release/py313.txt":
        raise P6LocalRuntimeError("P6 Python requirements path is invalid")
    snapshots = {
        "Containerfile": containerfile_snapshot.content,
        "containers/p6/runtime-lock.json": lock_snapshot.content,
        "containers/p6/verify_toolchain.py": verifier_snapshot.content,
        "requirements/release/py313.txt": requirements_snapshot.content,
    }
    if hashlib.sha256(snapshots["containers/p6/runtime-lock.json"]).hexdigest() != lock_sha:
        raise P6LocalRuntimeError("P6 runtime lock changed while being captured")
    containerfile_sha = hashlib.sha256(snapshots["Containerfile"]).hexdigest()
    requirements_sha = hashlib.sha256(snapshots["requirements/release/py313.txt"]).hexdigest()
    verifier_sha = hashlib.sha256(snapshots["containers/p6/verify_toolchain.py"]).hexdigest()
    build_archive = _minimal_build_context_archive(snapshots)
    tag = f"localhost/{repository}:p6-{git_revision[:12]}"
    _invoke(
        process_runner,
        [
            runtime,
            "build",
            "--pull=missing",
            "--platform=linux/amd64",
            "--tag",
            tag,
            "--build-arg",
            f"PYTHON_BASE_IMAGE={BASE_IMAGE_REF}",
            "--build-arg",
            f"ZSCOPE_GIT_REVISION={git_revision}",
            "--build-arg",
            f"ZSCOPE_RUNTIME_LOCK_SHA256={lock_sha}",
            "--build-arg",
            f"ZSCOPE_CONTAINERFILE_SHA256={containerfile_sha}",
            "-",
        ],
        name="P6 local image build",
        environment=subprocess_environment,
        stdin_bytes=build_archive,
    )
    inspect = _invoke(
        process_runner,
        [runtime, "image", "inspect", tag],
        name="P6 local image inspect",
        environment=subprocess_environment,
        expect_json=True,
    )
    if not isinstance(inspect, Mapping):
        raise P6LocalRuntimeError("P6 local image inspection is invalid")
    image_id = str(inspect.get("Id") or inspect.get("ID") or "")
    digest_candidates: list[str] = []
    for field in ("Digest", "digest"):
        raw = inspect.get(field)
        if isinstance(raw, str):
            digest_candidates.append(raw)
    raw_repo_digests = inspect.get("RepoDigests")
    if not isinstance(raw_repo_digests, list) or any(
        not isinstance(item, str) for item in raw_repo_digests
    ):
        raise P6LocalRuntimeError("P6 local image digest metadata is invalid")
    digest_candidates.extend(str(item).rsplit("@", 1)[-1] for item in raw_repo_digests)
    digests = sorted({item for item in digest_candidates if _DIGEST_RE.fullmatch(item)})
    if len(digests) != 1 or re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", image_id) is None:
        raise P6LocalRuntimeError("P6 local image lacks one immutable digest")
    digest = digests[0]
    config = inspect.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    image_environment, image_unset_keys = _partition_image_environment(inspect)
    if (
        not isinstance(config, Mapping)
        or "Entrypoint" not in config
        or config.get("Entrypoint") is not _IMAGE_EXPECTED_ENTRYPOINT
        or config.get("Cmd") != _IMAGE_EXPECTED_COMMAND
        or config.get("WorkingDir") != "/zscope-input"
    ):
        raise P6LocalRuntimeError("P6 local image command configuration is invalid")
    if not isinstance(labels, Mapping):
        raise P6LocalRuntimeError("P6 local image labels are missing")
    expected_labels = {
        IMAGE_LABEL_BASE_DIGEST: BASE_IMAGE_DIGEST,
        IMAGE_LABEL_REVISION: git_revision,
        IMAGE_LABEL_LOCK: lock_sha,
        IMAGE_LABEL_CONTAINERFILE: containerfile_sha,
    }
    if dict(labels) != expected_labels:
        raise P6LocalRuntimeError("P6 local image labels are invalid")
    if any(_sensitive_environment_key(key) for key in image_environment):
        raise P6LocalRuntimeError("P6 local image environment is invalid")
    if any(
        key.startswith("PYTHON") and key not in {"PYTHON_SHA256", "PYTHON_VERSION"}
        for key in image_environment
    ):
        raise P6LocalRuntimeError("P6 local image Python environment is invalid")
    probe_prefix = [
        runtime,
        "run",
        "--rm",
        "--network=none",
        "--log-driver=none",
        "--read-only",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--entrypoint",
        _IMAGE_PYTHON,
    ]
    for key in image_unset_keys:
        probe_prefix.extend(("--unsetenv", key))
    rootfs_probe = _invoke(
        process_runner,
        [
            *probe_prefix,
            f"localhost/{repository}@{digest}",
            "-I",
            "-S",
            "-c",
            _IMAGE_ROOTFS_PROBE_CODE,
        ],
        name="P6 image rootfs probe",
        environment=subprocess_environment,
        expect_json=True,
    )
    _validate_image_rootfs_probe(
        rootfs_probe,
        requirements_sha256=requirements_sha,
        verifier_sha256=verifier_sha,
    )
    probe_argv = [*probe_prefix]
    probe_argv.extend(
        (
            f"localhost/{repository}@{digest}",
            "-I",
            "-S",
            "/opt/zscope/verify_toolchain.py",
            "--json",
        )
    )
    probe = _invoke(
        process_runner,
        probe_argv,
        name="P6 image toolchain probe",
        environment=subprocess_environment,
        expect_json=True,
    )
    probe = _validate_toolchain_probe(probe)
    payload: dict[str, Any] = {
        "schema_version": IMAGE_PROVENANCE_SCHEMA_VERSION,
        "git_revision": git_revision,
        "platform": "linux/amd64",
        "base_image_ref": BASE_IMAGE_REF,
        "base_image_digest": BASE_IMAGE_DIGEST,
        "runtime_lock_sha256": lock_sha,
        "containerfile_sha256": containerfile_sha,
        "python_requirements_sha256": requirements_sha,
        "image_ref": f"localhost/{repository}@{digest}",
        "image_digest": digest,
        "image_id": image_id,
        "toolchain_probe": dict(probe),
        "credential_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["content_sha256"] = canonical_sha256(payload)
    validate_image_provenance(payload)
    _atomic_write_new_json(output, payload, name="P6 local image provenance")
    return payload


def _default_resolver(host: str, port: int) -> Sequence[tuple[str, int]]:
    rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = {(str(ipaddress.ip_address(str(row[4][0]))), int(row[4][1])) for row in rows}
    return tuple(sorted(addresses))


def _network_labels(value: Mapping[str, Any]) -> Mapping[str, str]:
    labels = value.get("Labels") if "Labels" in value else value.get("labels")
    return labels if isinstance(labels, Mapping) else {}


def _inspect_optional(
    runner: ProcessRunner,
    argv: Sequence[str],
    *,
    name: str,
    environment: Mapping[str, str],
) -> Mapping[str, Any] | None:
    result = runner(
        [str(item) for item in argv],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(environment),
    )
    if result.returncode != 0:
        return None
    value = _json_result(result, name=name)
    if not isinstance(value, Mapping):
        raise P6LocalRuntimeError(f"{name} is invalid")
    return value


def _partition_image_environment(
    inspect: Mapping[str, Any],
) -> tuple[dict[str, str], tuple[str, ...]]:
    config = inspect.get("Config")
    values = config.get("Env") if isinstance(config, Mapping) else None
    if not isinstance(values, list):
        raise P6LocalRuntimeError("P6 proxy image environment is invalid")
    retained: dict[str, str] = {}
    unset: set[str] = set()
    observed: set[str] = set()
    for raw in values:
        if not isinstance(raw, str) or "=" not in raw:
            raise P6LocalRuntimeError("P6 proxy image environment is invalid")
        key, value = raw.split("=", 1)
        if (
            not key
            or "\x00" in key
            or "\x00" in value
            or key in observed
            or _normalized_environment_key(key) != key
        ):
            raise P6LocalRuntimeError("P6 proxy image environment is invalid")
        observed.add(key)
        if _sensitive_environment_key(key):
            unset.add(key)
        else:
            retained[key] = value
    return retained, tuple(sorted(unset))


def _normalized_capabilities(value: Any, *, name: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise P6LocalRuntimeError(f"P6 proxy {name} are invalid")
    normalized = [item.upper().removeprefix("CAP_") for item in value]
    if len(normalized) != len(set(normalized)):
        raise P6LocalRuntimeError(f"P6 proxy {name} are invalid")
    return frozenset(normalized)


def _tmpfs_options(value: Any) -> frozenset[str]:
    if not isinstance(value, str):
        raise P6LocalRuntimeError("P6 proxy tmpfs is invalid")
    rows = [item.strip().lower() for item in value.split(",")]
    if not rows or any(not item for item in rows) or len(rows) != len(set(rows)):
        raise P6LocalRuntimeError("P6 proxy tmpfs is invalid")
    return frozenset(rows)


def _validate_proxy_mounts(value: Any, *, relay_source: str) -> None:
    if not isinstance(value, list):
        raise P6LocalRuntimeError("P6 proxy mounts are invalid")
    bind_count = 0
    tmpfs_count = 0
    for row in value:
        if not isinstance(row, Mapping):
            raise P6LocalRuntimeError("P6 proxy mounts are invalid")
        kind = str(row.get("Type") or row.get("type") or "").lower()
        destination = str(row.get("Destination") or row.get("destination") or "")
        source = str(row.get("Source") or row.get("source") or "")
        read_write = row.get("RW", row.get("rw"))
        if kind == "bind":
            bind_count += 1
            if (
                source != relay_source
                or destination != _PROXY_RELAY_DESTINATION
                or read_write is not False
            ):
                raise P6LocalRuntimeError("P6 proxy relay bind mount is invalid")
        elif kind == "tmpfs":
            tmpfs_count += 1
            if source not in {"", "tmpfs"} or destination != "/tmp" or read_write is not True:
                raise P6LocalRuntimeError("P6 proxy tmpfs mount is invalid")
        else:
            raise P6LocalRuntimeError("P6 proxy has an unexpected mount")
    if bind_count != 1 or tmpfs_count > 1:
        raise P6LocalRuntimeError("P6 proxy mount set is invalid")


def _validate_proxy_inspection(
    proxy: Mapping[str, Any],
    *,
    request: "ProxyProvisionRequest",
    image_provenance: Mapping[str, Any],
    endpoint_host: str,
    listen_port: int,
    upstream_rows: Sequence[str],
    policy_sha256: str,
    relay_sha256: str,
    relay_projection_sha256: str,
    relay_source: Path,
    upstreams_sha256: str,
    expected_environment: Mapping[str, str],
) -> None:
    config = proxy.get("Config")
    host_config = proxy.get("HostConfig")
    state = proxy.get("State")
    network_settings = proxy.get("NetworkSettings")
    networks = network_settings.get("Networks") if isinstance(network_settings, Mapping) else None
    mounts = proxy.get("Mounts")
    if (
        not isinstance(config, Mapping)
        or not isinstance(host_config, Mapping)
        or not isinstance(state, Mapping)
        or not isinstance(networks, Mapping)
    ):
        raise P6LocalRuntimeError("P6 proxy metadata is incomplete")

    image_name = proxy.get("ImageName")
    config_image = config.get("Image")
    if (
        proxy.get("Image") != image_provenance["image_id"]
        or image_name != request.image_ref
        or config_image != request.image_ref
    ):
        raise P6LocalRuntimeError("P6 proxy container image identity is invalid")
    expected_args = ["-I", "-S", _PROXY_RELAY_DESTINATION, "--listen-port", str(listen_port)]
    for row in upstream_rows:
        expected_args.extend(("--upstream", row))
    if proxy.get("Path") != _IMAGE_PYTHON or proxy.get("Args") != expected_args:
        raise P6LocalRuntimeError("P6 proxy command identity is invalid")

    labels = config.get("Labels")
    environment_rows = config.get("Env")
    if not isinstance(labels, Mapping) or not isinstance(environment_rows, list):
        raise P6LocalRuntimeError("P6 proxy configuration is incomplete")
    expected_labels = {
        IMAGE_LABEL_BASE_DIGEST: BASE_IMAGE_DIGEST,
        IMAGE_LABEL_REVISION: image_provenance["git_revision"],
        IMAGE_LABEL_LOCK: image_provenance["runtime_lock_sha256"],
        IMAGE_LABEL_CONTAINERFILE: image_provenance["containerfile_sha256"],
        PROXY_LABEL_ROLE: "model-endpoint-proxy",
        NETWORK_LABEL_SHA: policy_sha256,
        PROXY_LABEL_RELAY: relay_sha256,
        PROXY_LABEL_RELAY_PROJECTION: relay_projection_sha256,
        PROXY_LABEL_UPSTREAMS: upstreams_sha256,
    }
    if (
        state.get("Running") is not True
        or dict(labels) != expected_labels
        or config.get("User") != "65532:65532"
    ):
        raise P6LocalRuntimeError("P6 proxy identity is invalid")
    observed_environment: dict[str, str] = {}
    for row in environment_rows:
        if not isinstance(row, str) or "=" not in row:
            raise P6LocalRuntimeError("P6 proxy exposes credential-like environment metadata")
        key, value = row.split("=", 1)
        if (
            not key
            or key in observed_environment
            or _normalized_environment_key(key) != key
            or _sensitive_environment_key(key)
            or "\x00" in value
        ):
            raise P6LocalRuntimeError("P6 proxy exposes credential-like environment metadata")
        observed_environment[key] = value
    if observed_environment != dict(expected_environment):
        raise P6LocalRuntimeError("P6 proxy environment identity is invalid")

    security_options = host_config.get("SecurityOpt")
    pids_limit = host_config.get("PidsLimit")
    tmpfs = host_config.get("Tmpfs")
    log_config = host_config.get("LogConfig")
    if (
        host_config.get("ReadonlyRootfs") is not True
        or host_config.get("Privileged") is not False
        or security_options != ["no-new-privileges"]
        or isinstance(pids_limit, bool)
        or pids_limit != 64
        or _normalized_capabilities(host_config.get("CapDrop"), name="capability drops")
        != frozenset({"ALL"})
        or _normalized_capabilities(host_config.get("CapAdd"), name="capability additions")
        != frozenset({"NET_BIND_SERVICE"})
        or not isinstance(tmpfs, Mapping)
        or set(tmpfs) != {"/tmp"}
        or _tmpfs_options(tmpfs.get("/tmp")) != _PROXY_TMPFS_OPTIONS
        or not isinstance(log_config, Mapping)
        or set(log_config) != {"Type", "Config"}
        or log_config.get("Type") != "none"
        or log_config.get("Config") != {}
    ):
        raise P6LocalRuntimeError("P6 proxy security configuration is invalid")
    _validate_proxy_mounts(mounts, relay_source=str(relay_source))

    if set(networks) != {request.internal_network, request.egress_network}:
        raise P6LocalRuntimeError("P6 proxy network set is invalid")
    internal = networks.get(request.internal_network)
    egress = networks.get(request.egress_network)
    internal_aliases = internal.get("Aliases") if isinstance(internal, Mapping) else None
    egress_aliases = egress.get("Aliases") if isinstance(egress, Mapping) else None
    if internal_aliases != [endpoint_host] or egress_aliases != [request.proxy_container]:
        raise P6LocalRuntimeError("P6 proxy network aliases are invalid")


def _validate_image_inspection_projection(
    image_inspect: Mapping[str, Any],
    *,
    image_provenance: Mapping[str, Any],
) -> str:
    """Validate and hash the immutable subset of a live image inspection."""

    image_id = str(image_inspect.get("Id") or image_inspect.get("ID") or "")
    raw_repo_digests = image_inspect.get("RepoDigests")
    if not isinstance(raw_repo_digests, list) or any(
        not isinstance(item, str) for item in raw_repo_digests
    ):
        raise P6LocalRuntimeError("P6 proxy image digest metadata is invalid")
    digest_values = [str(item).rsplit("@", 1)[-1] for item in raw_repo_digests]
    for field in ("Digest", "digest"):
        value = image_inspect.get(field)
        if value is not None:
            if not isinstance(value, str):
                raise P6LocalRuntimeError("P6 proxy image digest metadata is invalid")
            digest_values.append(value)
    config = image_inspect.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    expected_labels = {
        IMAGE_LABEL_BASE_DIGEST: BASE_IMAGE_DIGEST,
        IMAGE_LABEL_REVISION: image_provenance["git_revision"],
        IMAGE_LABEL_LOCK: image_provenance["runtime_lock_sha256"],
        IMAGE_LABEL_CONTAINERFILE: image_provenance["containerfile_sha256"],
    }
    environment, unset_keys = _partition_image_environment(image_inspect)
    if (
        image_id != image_provenance["image_id"]
        or image_provenance["image_digest"] not in digest_values
        or not isinstance(config, Mapping)
        or "Entrypoint" not in config
        or config.get("Entrypoint") is not _IMAGE_EXPECTED_ENTRYPOINT
        or config.get("Cmd") != _IMAGE_EXPECTED_COMMAND
        or config.get("WorkingDir") != "/zscope-input"
        or not isinstance(labels, Mapping)
        or dict(labels) != expected_labels
    ):
        raise P6LocalRuntimeError("P6 proxy image identity is invalid")
    return str(
        canonical_sha256(
            {
                "image_ref": image_provenance["image_ref"],
                "image_id": image_id,
                "image_digest": image_provenance["image_digest"],
                "labels": expected_labels,
                "entrypoint": _IMAGE_EXPECTED_ENTRYPOINT,
                "command": _IMAGE_EXPECTED_COMMAND,
                "working_directory": "/zscope-input",
                "environment": dict(sorted(environment.items())),
                "unset_environment_keys": list(unset_keys),
            }
        )
    )


def _proxy_inspection_projections(
    proxy: Mapping[str, Any],
    *,
    request: "ProxyProvisionRequest",
    endpoint_host: str,
    relay_projection_sha256: str,
) -> dict[str, Any]:
    """Return closed hashes of all security-relevant live proxy projections."""

    config = cast(Mapping[str, Any], proxy["Config"])
    host_config = cast(Mapping[str, Any], proxy["HostConfig"])
    networks = cast(
        Mapping[str, Any], cast(Mapping[str, Any], proxy["NetworkSettings"])["Networks"]
    )
    environment_rows = cast(Sequence[str], config["Env"])
    environment = dict(row.split("=", 1) for row in environment_rows)
    network_names = sorted([request.internal_network, request.egress_network])
    network_aliases = {
        request.internal_network: list(
            cast(Mapping[str, Any], networks[request.internal_network])["Aliases"]
        ),
        request.egress_network: list(
            cast(Mapping[str, Any], networks[request.egress_network])["Aliases"]
        ),
    }
    command_projection = {
        "path": proxy["Path"],
        "args": list(cast(Sequence[str], proxy["Args"])),
    }
    security_projection = {
        "user": config["User"],
        "read_only_rootfs": host_config["ReadonlyRootfs"],
        "privileged": host_config["Privileged"],
        "security_opt": list(cast(Sequence[str], host_config["SecurityOpt"])),
        "pids_limit": host_config["PidsLimit"],
        "cap_drop": sorted(_normalized_capabilities(host_config["CapDrop"], name="drops")),
        "cap_add": sorted(_normalized_capabilities(host_config["CapAdd"], name="additions")),
        "tmpfs": {
            "/tmp": sorted(_tmpfs_options(cast(Mapping[str, Any], host_config["Tmpfs"])["/tmp"]))
        },
        "relay_mount": {
            "destination": _PROXY_RELAY_DESTINATION,
            "read_only": True,
            "relay_projection_sha256": relay_projection_sha256,
        },
    }
    log_driver_projection = dict(cast(Mapping[str, Any], host_config["LogConfig"]))
    result: dict[str, Any] = {
        "network_names": network_names,
        "network_aliases_sha256": canonical_sha256(
            {"network_names": network_names, "aliases": network_aliases}
        ),
        "command_projection_sha256": canonical_sha256(command_projection),
        "expected_environment_sha256": canonical_sha256(
            {"environment": dict(sorted(environment.items()))}
        ),
        "security_projection_sha256": canonical_sha256(security_projection),
        "log_driver_projection_sha256": canonical_sha256(log_driver_projection),
    }
    result["proxy_inspect_projection_sha256"] = canonical_sha256(
        {
            "proxy_container": request.proxy_container,
            "proxy_container_id": str(proxy.get("Id") or proxy.get("ID") or ""),
            "image_ref": request.image_ref,
            "image_id": proxy["Image"],
            "endpoint_host": endpoint_host,
            **result,
        }
    )
    return result


def _create_private_relay_snapshot(content: bytes) -> tuple[Path, _FileSnapshot]:
    directory = Path(tempfile.mkdtemp(prefix="zscope-p6-relay-"))
    os.chmod(directory, 0o700)
    _validate_private_directory(directory, empty=True, name="P6 relay snapshot directory")
    digest = hashlib.sha256(content).hexdigest()
    path = directory / f"p6_tcp_relay-{digest}.py"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o400)
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(path, 0o444)
        snapshot = _snapshot_regular_file(path, name="P6 relay snapshot")
        if (
            snapshot.content != content
            or (os.name == "posix" and stat.S_IMODE(snapshot.mode) != 0o444)
            or (_current_uid() is not None and snapshot.uid != _current_uid())
        ):
            raise P6LocalRuntimeError("P6 relay snapshot identity is invalid")
        return path, snapshot
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        try:
            directory.rmdir()
        except OSError:
            pass
        raise


def _existing_relay_source(proxy: Mapping[str, Any]) -> Path:
    mounts = proxy.get("Mounts")
    if not isinstance(mounts, list):
        raise P6LocalRuntimeError("P6 proxy mounts are invalid")
    sources = [
        str(row.get("Source") or row.get("source") or "")
        for row in mounts
        if isinstance(row, Mapping)
        and str(row.get("Type") or row.get("type") or "").lower() == "bind"
        and str(row.get("Destination") or row.get("destination") or "") == _PROXY_RELAY_DESTINATION
    ]
    if len(sources) != 1 or not Path(sources[0]).is_absolute():
        raise P6LocalRuntimeError("P6 proxy relay projection is invalid")
    return Path(sources[0])


def _validate_private_relay_snapshot(path: Path, content: bytes) -> _FileSnapshot:
    try:
        parent = path.parent.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise P6LocalRuntimeError("P6 proxy relay snapshot is unavailable") from exc
    if resolved != path or not parent.name.startswith("zscope-p6-relay-"):
        raise P6LocalRuntimeError("P6 proxy relay snapshot path is invalid")
    _validate_private_directory(parent, empty=False, name="P6 relay snapshot directory")
    try:
        rows = tuple(parent.iterdir())
    except OSError as exc:
        raise P6LocalRuntimeError("P6 relay snapshot directory is unavailable") from exc
    if rows != (path,):
        raise P6LocalRuntimeError("P6 relay snapshot directory contents are invalid")
    snapshot = _snapshot_regular_file(path, name="P6 relay snapshot")
    try:
        links = path.lstat().st_nlink
    except OSError as exc:
        raise P6LocalRuntimeError("P6 relay snapshot is unavailable") from exc
    if (
        snapshot.content != content
        or (os.name == "posix" and stat.S_IMODE(snapshot.mode) != 0o444)
        or links != 1
        or (_current_uid() is not None and snapshot.uid != _current_uid())
    ):
        raise P6LocalRuntimeError("P6 relay snapshot identity is invalid")
    return snapshot


@dataclass(frozen=True)
class ProxyProvisionRequest:
    runtime: str
    image_ref: str
    internal_network: str
    egress_network: str
    proxy_container: str
    relay_path: Path
    image_provenance_path: Path

    def validate(self) -> None:
        if self.runtime != "podman" or not _DIGEST_RE.fullmatch(self.image_ref.rsplit("@", 1)[-1]):
            raise P6LocalRuntimeError("P6 proxy image must be digest pinned")
        for value in (self.internal_network, self.egress_network, self.proxy_container):
            if _SAFE_OCI_NAME_RE.fullmatch(value) is None:
                raise P6LocalRuntimeError("P6 proxy OCI name is invalid")
        if self.internal_network == self.egress_network:
            raise P6LocalRuntimeError("P6 proxy internal and egress networks must differ")
        _file_sha256(self.relay_path)
        provenance = load_image_provenance(self.image_provenance_path)
        if provenance["image_ref"] != self.image_ref:
            raise P6LocalRuntimeError("P6 proxy image provenance does not match")


def provision_transparent_proxy(
    *,
    request: ProxyProvisionRequest,
    provider_contract: ProviderRuntimeContract,
    output: Path,
    process_runner: ProcessRunner = subprocess.run,
    address_resolver: AddressResolver = _default_resolver,
) -> dict[str, Any]:
    """Idempotently provision one exact raw TCP relay and internal network."""

    with _private_podman_environment() as environment:
        return _provision_transparent_proxy(
            request=request,
            provider_contract=provider_contract,
            output=output,
            process_runner=process_runner,
            address_resolver=address_resolver,
            subprocess_environment=environment,
        )


def _provision_transparent_proxy(
    *,
    request: ProxyProvisionRequest,
    provider_contract: ProviderRuntimeContract,
    output: Path,
    subprocess_environment: Mapping[str, str],
    process_runner: ProcessRunner = subprocess.run,
    address_resolver: AddressResolver = _default_resolver,
) -> dict[str, Any]:
    request.validate()
    image_provenance = load_image_provenance(request.image_provenance_path)
    policy_environment = {
        "Z_SCOPE_BENCHMARK_OCI_NETWORK": request.internal_network,
        "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": request.proxy_container,
    }
    policy = OciNetworkPolicy.from_provider_contract(policy_environment, provider_contract)
    parsed_port = int(policy.endpoint_origin.rsplit(":", 1)[1])
    addresses = tuple(sorted(set(address_resolver(policy.endpoint_host, parsed_port))))
    if not addresses or any(
        str(ipaddress.ip_address(host)) != host or port != parsed_port for host, port in addresses
    ):
        raise P6LocalRuntimeError("P6 proxy upstream address resolution is invalid")
    relay_source_input = _snapshot_regular_file(request.relay_path, name="P6 relay source")
    relay_sha = relay_source_input.sha256
    upstream_rows = [
        f"[{host}]:{port}" if ":" in host else f"{host}:{port}" for host, port in addresses
    ]
    upstreams_sha = canonical_sha256({"upstreams": upstream_rows})

    image_inspect = _invoke(
        process_runner,
        [request.runtime, "image", "inspect", request.image_ref],
        name="P6 proxy image inspect",
        environment=subprocess_environment,
        expect_json=True,
    )
    if not isinstance(image_inspect, Mapping):
        raise P6LocalRuntimeError("P6 proxy image inspection is invalid")
    image_id = str(image_inspect.get("Id") or image_inspect.get("ID") or "")
    digest = request.image_ref.rsplit("@", 1)[1]
    raw_repo_digests = image_inspect.get("RepoDigests")
    if not isinstance(raw_repo_digests, list) or any(
        not isinstance(item, str) for item in raw_repo_digests
    ):
        raise P6LocalRuntimeError("P6 proxy image digest metadata is invalid")
    digest_values = [str(item).rsplit("@", 1)[-1] for item in raw_repo_digests]
    for field in ("Digest", "digest"):
        value = image_inspect.get(field)
        if value is not None:
            if not isinstance(value, str):
                raise P6LocalRuntimeError("P6 proxy image digest metadata is invalid")
            digest_values.append(value)
    image_config = image_inspect.get("Config")
    image_labels = image_config.get("Labels") if isinstance(image_config, Mapping) else None
    expected_image_labels = {
        IMAGE_LABEL_BASE_DIGEST: BASE_IMAGE_DIGEST,
        IMAGE_LABEL_REVISION: image_provenance["git_revision"],
        IMAGE_LABEL_LOCK: image_provenance["runtime_lock_sha256"],
        IMAGE_LABEL_CONTAINERFILE: image_provenance["containerfile_sha256"],
    }
    if (
        image_id != image_provenance["image_id"]
        or digest != image_provenance["image_digest"]
        or digest not in digest_values
        or not isinstance(image_labels, Mapping)
        or dict(image_labels) != expected_image_labels
    ):
        raise P6LocalRuntimeError("P6 proxy image identity is invalid")
    image_inspect_projection_sha = _validate_image_inspection_projection(
        image_inspect,
        image_provenance=image_provenance,
    )
    expected_proxy_environment, unset_keys = _partition_image_environment(image_inspect)

    internal = _inspect_optional(
        process_runner,
        [request.runtime, "network", "inspect", request.internal_network],
        name="P6 internal network inspect",
        environment=subprocess_environment,
    )
    if internal is None:
        _invoke(
            process_runner,
            [
                request.runtime,
                "network",
                "create",
                "--internal",
                "--label",
                f"{NETWORK_LABEL_MODE}=model-endpoint-only",
                "--label",
                f"{NETWORK_LABEL_SHA}={policy.policy_sha256}",
                request.internal_network,
            ],
            name="P6 internal network create",
            environment=subprocess_environment,
        )
        internal = _invoke(
            process_runner,
            [request.runtime, "network", "inspect", request.internal_network],
            name="P6 internal network inspect",
            environment=subprocess_environment,
            expect_json=True,
        )
    if not isinstance(internal, Mapping):
        raise P6LocalRuntimeError("P6 internal network inspection is invalid")
    internal_flag = internal.get("Internal", internal.get("internal"))
    if internal_flag is not True or dict(_network_labels(internal)) != {
        NETWORK_LABEL_MODE: "model-endpoint-only",
        NETWORK_LABEL_SHA: policy.policy_sha256,
    }:
        raise P6LocalRuntimeError("P6 internal network conflicts with the policy")

    egress = _inspect_optional(
        process_runner,
        [request.runtime, "network", "inspect", request.egress_network],
        name="P6 egress network inspect",
        environment=subprocess_environment,
    )
    if egress is None:
        _invoke(
            process_runner,
            [
                request.runtime,
                "network",
                "create",
                "--label",
                f"{EGRESS_LABEL_ROLE}=model-endpoint-egress",
                "--label",
                f"{NETWORK_LABEL_SHA}={policy.policy_sha256}",
                request.egress_network,
            ],
            name="P6 egress network create",
            environment=subprocess_environment,
        )
        egress = _invoke(
            process_runner,
            [request.runtime, "network", "inspect", request.egress_network],
            name="P6 egress network inspect",
            environment=subprocess_environment,
            expect_json=True,
        )
    if not isinstance(egress, Mapping):
        raise P6LocalRuntimeError("P6 egress network inspection is invalid")
    if egress.get("Internal", egress.get("internal")) is True or dict(_network_labels(egress)) != {
        EGRESS_LABEL_ROLE: "model-endpoint-egress",
        NETWORK_LABEL_SHA: policy.policy_sha256,
    }:
        raise P6LocalRuntimeError("P6 egress network conflicts with the policy")

    proxy = _inspect_optional(
        process_runner,
        [request.runtime, "inspect", request.proxy_container],
        name="P6 proxy inspect",
        environment=subprocess_environment,
    )
    created = False
    if proxy is None:
        relay_source, relay_snapshot = _create_private_relay_snapshot(relay_source_input.content)
    else:
        relay_source = _existing_relay_source(proxy)
        relay_snapshot = _validate_private_relay_snapshot(relay_source, relay_source_input.content)
    relay_projection_sha = _relay_projection_sha256(relay_snapshot)
    if proxy is None:
        argv = [
            request.runtime,
            "run",
            "--detach",
            "--pull=never",
            "--name",
            request.proxy_container,
            "--network",
            "none",
            "--read-only",
            "--cap-drop=all",
            "--cap-add=net_bind_service",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--user=65532:65532",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--log-driver=none",
            "--label",
            f"{PROXY_LABEL_ROLE}=model-endpoint-proxy",
            "--label",
            f"{NETWORK_LABEL_SHA}={policy.policy_sha256}",
            "--label",
            f"{PROXY_LABEL_RELAY}={relay_sha}",
            "--label",
            f"{PROXY_LABEL_RELAY_PROJECTION}={relay_projection_sha}",
            "--label",
            f"{PROXY_LABEL_UPSTREAMS}={upstreams_sha}",
            "--mount",
            (f"type=bind,src={relay_source}," "dst=/opt/zscope/p6_tcp_relay.py,readonly"),
        ]
        for key in unset_keys:
            argv.extend(("--unsetenv", key))
        argv.extend(
            (
                request.image_ref,
                _IMAGE_PYTHON,
                "-I",
                "-S",
                "/opt/zscope/p6_tcp_relay.py",
                "--listen-port",
                str(parsed_port),
            )
        )
        for row in upstream_rows:
            argv.extend(("--upstream", row))
        _invoke(
            process_runner,
            argv,
            name="P6 proxy container create",
            environment=subprocess_environment,
        )
        unnetworked_proxy = _invoke(
            process_runner,
            [request.runtime, "inspect", request.proxy_container],
            name="P6 unnetworked proxy inspect",
            environment=subprocess_environment,
            expect_json=True,
        )
        if not isinstance(unnetworked_proxy, Mapping):
            raise P6LocalRuntimeError("P6 unnetworked proxy inspection is invalid")
        initial_container_id = str(unnetworked_proxy.get("Id") or unnetworked_proxy.get("ID") or "")
        if _existing_relay_source(unnetworked_proxy) != relay_source:
            raise P6LocalRuntimeError("P6 proxy relay projection is invalid")
        current_relay_snapshot = _validate_private_relay_snapshot(
            relay_source, relay_source_input.content
        )
        live_projection = _validate_live_relay_projection(
            runtime=request.runtime,
            proxy_container_id=initial_container_id,
            expected=current_relay_snapshot,
            process_runner=process_runner,
            environment=subprocess_environment,
        )
        if live_projection != relay_projection_sha:
            raise P6LocalRuntimeError("P6 proxy live relay projection is invalid")
        _invoke(
            process_runner,
            [
                request.runtime,
                "network",
                "connect",
                "--alias",
                request.proxy_container,
                request.egress_network,
                request.proxy_container,
            ],
            name="P6 proxy egress network attach",
            environment=subprocess_environment,
        )
        _invoke(
            process_runner,
            [
                request.runtime,
                "network",
                "connect",
                "--alias",
                policy.endpoint_host,
                request.internal_network,
                request.proxy_container,
            ],
            name="P6 proxy internal network attach",
            environment=subprocess_environment,
        )
        proxy = _invoke(
            process_runner,
            [request.runtime, "inspect", request.proxy_container],
            name="P6 proxy inspect",
            environment=subprocess_environment,
            expect_json=True,
        )
        created = True
    if not isinstance(proxy, Mapping):
        raise P6LocalRuntimeError("P6 proxy inspection is invalid")
    current_relay_snapshot = _validate_private_relay_snapshot(
        relay_source, relay_source_input.content
    )
    if _relay_projection_sha256(current_relay_snapshot) != relay_projection_sha:
        raise P6LocalRuntimeError("P6 proxy relay projection changed during provision")
    proxy_container_id = str(proxy.get("Id") or proxy.get("ID") or "")
    live_projection = _validate_live_relay_projection(
        runtime=request.runtime,
        proxy_container_id=proxy_container_id,
        expected=current_relay_snapshot,
        process_runner=process_runner,
        environment=subprocess_environment,
    )
    if live_projection != relay_projection_sha:
        raise P6LocalRuntimeError("P6 proxy live relay projection is invalid")
    _validate_proxy_inspection(
        proxy,
        request=request,
        image_provenance=image_provenance,
        endpoint_host=policy.endpoint_host,
        listen_port=parsed_port,
        upstream_rows=upstream_rows,
        policy_sha256=policy.policy_sha256,
        relay_sha256=relay_sha,
        relay_projection_sha256=relay_projection_sha,
        relay_source=relay_source,
        upstreams_sha256=upstreams_sha,
        expected_environment=expected_proxy_environment,
    )
    projections = _proxy_inspection_projections(
        proxy,
        request=request,
        endpoint_host=policy.endpoint_host,
        relay_projection_sha256=relay_projection_sha,
    )
    if re.fullmatch(r"[0-9a-f]{64}", proxy_container_id) is None:
        raise P6LocalRuntimeError("P6 proxy container identity is missing or truncated")
    payload: dict[str, Any] = {
        "schema_version": PROXY_PROVISION_SCHEMA_VERSION,
        "created": created,
        "image_ref": request.image_ref,
        "image_id": image_provenance["image_id"],
        "provider_identity_sha256": provider_contract.identity_sha256,
        "network_name": request.internal_network,
        "egress_network_name": request.egress_network,
        "network_names": projections["network_names"],
        "network_aliases_sha256": projections["network_aliases_sha256"],
        "proxy_container": request.proxy_container,
        "proxy_container_id": proxy_container_id,
        "endpoint_origin": policy.endpoint_origin,
        "endpoint_host": policy.endpoint_host,
        "network_policy_sha256": policy.policy_sha256,
        "relay_sha256": relay_sha,
        "relay_projection_sha256": relay_projection_sha,
        "upstreams_sha256": upstreams_sha,
        "upstream_count": len(upstream_rows),
        "command_projection_sha256": projections["command_projection_sha256"],
        "expected_environment_sha256": projections["expected_environment_sha256"],
        "credential_environment_keys": [],
        "security_projection_sha256": projections["security_projection_sha256"],
        "log_driver_projection_sha256": projections["log_driver_projection_sha256"],
        "image_inspect_projection_sha256": image_inspect_projection_sha,
        "proxy_inspect_projection_sha256": projections["proxy_inspect_projection_sha256"],
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["content_sha256"] = canonical_sha256(payload)
    _atomic_write_new_json(output, payload, name="P6 proxy provenance")
    return payload


def build_expected_proxy_attestation(
    *,
    request: ProxyProvisionRequest,
    provider_contract: ProviderRuntimeContract,
    toolchain_evidence_path: Path,
    proxy_provision_path: Path,
    expected_lineage: Mapping[str, Any],
    output: Path,
    process_runner: ProcessRunner = subprocess.run,
) -> dict[str, Any]:
    """Create one closed cross-job expectation from frozen receipts and live OCI state.

    This operation is intentionally credential-free.  It reads each source
    receipt once, revalidates its exact lineage, inspects the current image and
    container in a closed Podman environment, and publishes one new immutable
    attestation.  The API-key environment is neither accepted nor forwarded.
    """

    with _private_podman_environment() as environment:
        return _build_expected_proxy_attestation(
            request=request,
            provider_contract=provider_contract,
            toolchain_evidence_path=toolchain_evidence_path,
            proxy_provision_path=proxy_provision_path,
            expected_lineage=expected_lineage,
            output=output,
            subprocess_environment=environment,
            process_runner=process_runner,
        )


def build_bootstrap_proxy_attestation(
    *,
    request: ProxyProvisionRequest,
    provider_contract: ProviderRuntimeContract,
    image_provenance_path: Path,
    proxy_provision_path: Path,
    expected_lineage: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the credential-free expectation used by the toolchain preflight.

    The final expected-proxy attestation cannot exist until toolchain evidence
    exists.  This closed, non-release object breaks that dependency cycle by
    binding the already verified image and proxy receipts.  It is accepted by
    :class:`RootlessOciExecutor` only for one credential-free ``preflight``
    phase; it cannot authorize a scan or a release claim.
    """

    request.validate()
    expected_lineage_fields = {
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "repository",
    }
    if set(expected_lineage) != expected_lineage_fields:
        raise P6LocalRuntimeError("P6 bootstrap lineage fields are invalid")
    run_id = expected_lineage.get("workflow_run_id")
    run_attempt = expected_lineage.get("workflow_run_attempt")
    attempt_id = expected_lineage.get("attempt_id")
    repository = expected_lineage.get("repository")
    if (
        not isinstance(run_id, str)
        or re.fullmatch(r"[1-9][0-9]*", run_id) is None
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt < 1
        or attempt_id != f"p6-{run_id}-{run_attempt}"
        or not isinstance(repository, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
    ):
        raise P6LocalRuntimeError("P6 bootstrap lineage is invalid")

    image_bytes = read_regular_file_once(image_provenance_path.absolute())
    proxy_bytes = read_regular_file_once(proxy_provision_path.absolute())
    image_raw = load_json_bytes_strict(image_bytes, name="P6 image provenance")
    proxy_raw = load_json_bytes_strict(proxy_bytes, name="P6 proxy provision")
    if not isinstance(image_raw, Mapping) or not isinstance(proxy_raw, Mapping):
        raise P6LocalRuntimeError("P6 bootstrap receipts must contain objects")
    try:
        image_provenance = validate_image_provenance(image_raw)
        proxy_provision = dict(validate_proxy_provision(proxy_raw))
    except Exception as exc:
        raise P6LocalRuntimeError("P6 bootstrap receipt is invalid") from exc
    if (
        request.image_ref != image_provenance["image_ref"]
        or request.image_ref != proxy_provision["image_ref"]
        or image_provenance["image_id"] != proxy_provision["image_id"]
        or request.internal_network != proxy_provision["network_name"]
        or request.egress_network != proxy_provision["egress_network_name"]
        or request.proxy_container != proxy_provision["proxy_container"]
        or provider_contract.identity_sha256 != proxy_provision["provider_identity_sha256"]
    ):
        raise P6LocalRuntimeError("P6 bootstrap receipt lineage is invalid")
    policy = OciNetworkPolicy.from_provider_contract(
        {
            "Z_SCOPE_BENCHMARK_OCI_NETWORK": request.internal_network,
            "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": request.proxy_container,
        },
        provider_contract,
    )
    if (
        policy.policy_sha256 != proxy_provision["network_policy_sha256"]
        or policy.endpoint_origin != proxy_provision["endpoint_origin"]
        or policy.endpoint_host != proxy_provision["endpoint_host"]
    ):
        raise P6LocalRuntimeError("P6 bootstrap provider policy is invalid")

    payload: dict[str, Any] = {
        "schema_version": P6_BOOTSTRAP_PROXY_ATTESTATION_SCHEMA_VERSION,
        "workflow_run_id": run_id,
        "workflow_run_attempt": run_attempt,
        "attempt_id": attempt_id,
        "repository": repository,
        "image_provenance_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "image_provenance_content_sha256": image_provenance["content_sha256"],
        "proxy_provision_sha256": hashlib.sha256(proxy_bytes).hexdigest(),
        "proxy_provision_content_sha256": proxy_provision["content_sha256"],
        **{
            field: proxy_provision[field]
            for field in (
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
            )
        },
        "bootstrap_preflight_only": True,
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["content_sha256"] = canonical_sha256(payload)
    return payload


def _build_expected_proxy_attestation(
    *,
    request: ProxyProvisionRequest,
    provider_contract: ProviderRuntimeContract,
    toolchain_evidence_path: Path,
    proxy_provision_path: Path,
    expected_lineage: Mapping[str, Any],
    output: Path,
    subprocess_environment: Mapping[str, str],
    process_runner: ProcessRunner = subprocess.run,
) -> dict[str, Any]:
    request.validate()
    toolchain_bytes = read_regular_file_once(toolchain_evidence_path.absolute())
    provenance_bytes = read_regular_file_once(request.image_provenance_path.absolute())
    proxy_bytes = read_regular_file_once(proxy_provision_path.absolute())
    toolchain_raw = load_json_bytes_strict(toolchain_bytes, name="P6 toolchain evidence")
    if not isinstance(toolchain_raw, Mapping):
        raise P6LocalRuntimeError("P6 toolchain evidence must contain one object")
    try:
        restored = validate_toolchain_provenance_files(
            toolchain_raw,
            request.image_provenance_path.absolute(),
            proxy_provision_path.absolute(),
            expected_lineage=expected_lineage,
            _source_file_bytes=(provenance_bytes, proxy_bytes),
        )
    except Exception as exc:
        raise P6LocalRuntimeError("P6 raw proxy receipt lineage is invalid") from exc
    image_provenance = dict(restored["image_provenance"])
    receipt = dict(restored["proxy_provision"])
    if (
        request.image_ref != receipt["image_ref"]
        or request.image_ref != image_provenance["image_ref"]
        or request.proxy_container != receipt["proxy_container"]
        or request.internal_network != receipt["network_name"]
        or request.egress_network != receipt["egress_network_name"]
        or provider_contract.identity_sha256 != receipt["provider_identity_sha256"]
    ):
        raise P6LocalRuntimeError("P6 expected proxy request lineage is invalid")

    policy = OciNetworkPolicy.from_provider_contract(
        {
            "Z_SCOPE_BENCHMARK_OCI_NETWORK": request.internal_network,
            "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": request.proxy_container,
        },
        provider_contract,
    )
    if (
        policy.policy_sha256 != receipt["network_policy_sha256"]
        or policy.endpoint_origin != receipt["endpoint_origin"]
        or policy.endpoint_host != receipt["endpoint_host"]
    ):
        raise P6LocalRuntimeError("P6 expected proxy policy lineage is invalid")

    image_inspect = _invoke(
        process_runner,
        [request.runtime, "image", "inspect", request.image_ref],
        name="P6 expected proxy image inspect",
        environment=subprocess_environment,
        expect_json=True,
    )
    proxy_inspect = _invoke(
        process_runner,
        [request.runtime, "inspect", request.proxy_container],
        name="P6 expected proxy container inspect",
        environment=subprocess_environment,
        expect_json=True,
    )
    if not isinstance(image_inspect, Mapping) or not isinstance(proxy_inspect, Mapping):
        raise P6LocalRuntimeError("P6 expected proxy live inspection is invalid")
    image_projection_sha = _validate_image_inspection_projection(
        image_inspect,
        image_provenance=image_provenance,
    )
    proxy_id = str(proxy_inspect.get("Id") or proxy_inspect.get("ID") or "")
    if (
        re.fullmatch(r"[0-9a-f]{64}", proxy_id) is None
        or proxy_id != receipt["proxy_container_id"]
        or proxy_inspect.get("Image") != receipt["image_id"]
    ):
        raise P6LocalRuntimeError("P6 expected proxy live container identity is invalid")

    parsed = urlsplit(policy.endpoint_origin)
    listen_port = parsed.port or 443
    args = proxy_inspect.get("Args")
    expected_prefix = [
        "-I",
        "-S",
        _PROXY_RELAY_DESTINATION,
        "--listen-port",
        str(listen_port),
    ]
    if (
        proxy_inspect.get("Path") != _IMAGE_PYTHON
        or not isinstance(args, list)
        or args[: len(expected_prefix)] != expected_prefix
        or any(not isinstance(item, str) for item in args)
    ):
        raise P6LocalRuntimeError("P6 expected proxy command identity is invalid")
    trailing = args[len(expected_prefix) :]
    if len(trailing) % 2 or any(
        trailing[index] != "--upstream" for index in range(0, len(trailing), 2)
    ):
        raise P6LocalRuntimeError("P6 expected proxy upstream command is invalid")
    upstream_rows = trailing[1::2]
    if (
        canonical_sha256({"upstreams": upstream_rows}) != receipt["upstreams_sha256"]
        or len(upstream_rows) != receipt["upstream_count"]
    ):
        raise P6LocalRuntimeError("P6 expected proxy upstream set is invalid")
    relay_input = _snapshot_regular_file(request.relay_path, name="P6 relay source")
    relay_source = _existing_relay_source(proxy_inspect)
    relay_snapshot = _validate_private_relay_snapshot(relay_source, relay_input.content)
    relay_projection_sha = _validate_live_relay_projection(
        runtime=request.runtime,
        proxy_container_id=proxy_id,
        expected=relay_snapshot,
        process_runner=process_runner,
        environment=subprocess_environment,
    )
    if (
        relay_input.sha256 != receipt["relay_sha256"]
        or relay_projection_sha != receipt["relay_projection_sha256"]
    ):
        raise P6LocalRuntimeError("P6 expected proxy relay identity is invalid")
    expected_environment, _ = _partition_image_environment(image_inspect)
    _validate_proxy_inspection(
        proxy_inspect,
        request=request,
        image_provenance=image_provenance,
        endpoint_host=policy.endpoint_host,
        listen_port=listen_port,
        upstream_rows=upstream_rows,
        policy_sha256=policy.policy_sha256,
        relay_sha256=relay_input.sha256,
        relay_projection_sha256=relay_projection_sha,
        relay_source=relay_source,
        upstreams_sha256=receipt["upstreams_sha256"],
        expected_environment=expected_environment,
    )
    projections = _proxy_inspection_projections(
        proxy_inspect,
        request=request,
        endpoint_host=policy.endpoint_host,
        relay_projection_sha256=relay_projection_sha,
    )
    for field in (
        "network_names",
        "network_aliases_sha256",
        "command_projection_sha256",
        "expected_environment_sha256",
        "security_projection_sha256",
        "log_driver_projection_sha256",
        "proxy_inspect_projection_sha256",
    ):
        if projections[field] != receipt[field]:
            raise P6LocalRuntimeError("P6 expected proxy live projection is invalid")
    if image_projection_sha != receipt["image_inspect_projection_sha256"]:
        raise P6LocalRuntimeError("P6 expected proxy image projection is invalid")

    payload: dict[str, Any] = {
        "schema_version": EXPECTED_PROXY_ATTESTATION_SCHEMA_VERSION,
        "workflow_run_id": expected_lineage["workflow_run_id"],
        "workflow_run_attempt": expected_lineage["workflow_run_attempt"],
        "attempt_id": expected_lineage["attempt_id"],
        "control_plane_commit": expected_lineage["control_plane_commit"],
        "candidate_sha256": expected_lineage["candidate_sha256"],
        "candidate_git_sha": expected_lineage["candidate_git_sha"],
        "candidate_git_tree": expected_lineage["candidate_git_tree"],
        "toolchain_evidence_sha256": hashlib.sha256(toolchain_bytes).hexdigest(),
        "toolchain_evidence_content_sha256": toolchain_raw["evidence_sha256"],
        "image_provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "image_provenance_content_sha256": image_provenance["content_sha256"],
        "proxy_provision_sha256": hashlib.sha256(proxy_bytes).hexdigest(),
        "proxy_provision_content_sha256": receipt["content_sha256"],
        "image_ref": receipt["image_ref"],
        "image_id": receipt["image_id"],
        "provider_identity_sha256": receipt["provider_identity_sha256"],
        "network_name": receipt["network_name"],
        "egress_network_name": receipt["egress_network_name"],
        "network_names": receipt["network_names"],
        "network_aliases_sha256": receipt["network_aliases_sha256"],
        "proxy_container": receipt["proxy_container"],
        "proxy_container_id": receipt["proxy_container_id"],
        "endpoint_origin": receipt["endpoint_origin"],
        "endpoint_host": receipt["endpoint_host"],
        "network_policy_sha256": receipt["network_policy_sha256"],
        "relay_sha256": receipt["relay_sha256"],
        "relay_projection_sha256": receipt["relay_projection_sha256"],
        "upstreams_sha256": receipt["upstreams_sha256"],
        "upstream_count": receipt["upstream_count"],
        "command_projection_sha256": receipt["command_projection_sha256"],
        "expected_environment_sha256": receipt["expected_environment_sha256"],
        "credential_environment_keys": [],
        "security_projection_sha256": receipt["security_projection_sha256"],
        "log_driver_projection_sha256": receipt["log_driver_projection_sha256"],
        "image_inspect_projection_sha256": receipt["image_inspect_projection_sha256"],
        "proxy_inspect_projection_sha256": receipt["proxy_inspect_projection_sha256"],
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["content_sha256"] = canonical_sha256(payload)
    try:
        validate_expected_proxy_attestation(payload)
    except Exception as exc:
        raise P6LocalRuntimeError("P6 expected proxy attestation is invalid") from exc
    _atomic_write_new_json(output, payload, name="P6 expected proxy attestation")
    return payload


__all__ = [
    "BASE_IMAGE_DIGEST",
    "BASE_IMAGE_REF",
    "IMAGE_PROVENANCE_SCHEMA_VERSION",
    "P6LocalRuntimeError",
    "PROXY_PROVISION_SCHEMA_VERSION",
    "ProxyProvisionRequest",
    "RUNTIME_LOCK_SCHEMA_VERSION",
    "build_bootstrap_proxy_attestation",
    "build_expected_proxy_attestation",
    "build_toolchain_image",
    "load_runtime_lock",
    "load_image_provenance",
    "provision_transparent_proxy",
    "validate_runtime_lock",
    "validate_image_provenance",
]
