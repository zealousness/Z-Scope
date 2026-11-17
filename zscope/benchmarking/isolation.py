"""Fail-closed execution plans for answer-isolated OCI benchmark scans."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

ISOLATION_SCHEMA_VERSION = "zscope.benchmark-isolation.v1"
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


class BenchmarkIsolationError(RuntimeError):
    """Raised when a requested isolation claim cannot be established."""


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


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


def _nested(mapping: Mapping[str, Any], *path: str) -> Any:
    value: Any = mapping
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


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
        network = str(environment.get("Z_SCOPE_BENCHMARK_OCI_NETWORK") or "").strip()
        proxy = str(environment.get("Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER") or "").strip()
        endpoint = str(environment.get("Z_SCOPE_LLM_BASE_URL") or "").strip()
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
            ],
            "argv": list(self.argv),
            "environment_keys": list(self.environment_keys),
            "network_mode": self.network_mode,
            "network_name": self.network_name,
            "network_policy_sha256": self.network_policy_sha256,
            "truth_mounted": False,
            "repository_mounted": False,
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
    roots = (source, output, cache)
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
    allowed_environment = tuple(
        sorted(key for key in environment if key in _PASSTHROUGH_ENVIRONMENT)
    )
    policy: Optional[OciNetworkPolicy]
    try:
        policy = OciNetworkPolicy.from_environment(environment)
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
        network_mode=("model-endpoint-only" if policy is not None else "unverified"),
        network_name=(policy.network_name if policy is not None else ""),
        network_policy_sha256=(policy.policy_sha256 if policy is not None else ""),
    )


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]


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
    left = str(left or "")
    right = str(right or "")
    return bool(
        left and right and (left == right or left.startswith(right) or right.startswith(left))
    )


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
        process_runner: ProcessRunner = subprocess.run,
        which: Optional[Callable[[str], Optional[str]]] = None,
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
        self.environment = {
            str(key): str(value)
            for key, value in environment.items()
            if key not in TRUTH_ENVIRONMENT_KEYS
            and "GROUND_TRUTH" not in str(key).upper()
            and "BENCHMARK_TRUTH" not in str(key).upper()
        }
        self.network_policy = OciNetworkPolicy.from_environment(self.environment)
        self._run = process_runner
        self._preflight: Optional[Dict[str, Any]] = None
        self._phases: list[Dict[str, Any]] = []
        self._validate_roots()

    def _validate_roots(self) -> None:
        for label, path in (
            ("scan input", self.scan_input),
            ("artifact output", self.artifact_output),
            ("cache output", self.cache_output),
        ):
            if not path.is_dir():
                raise BenchmarkIsolationError(f"{label} does not exist: {path}")
        roots = (self.scan_input, self.artifact_output, self.cache_output)
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

    def _invoke(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        runtime_environment = dict(os.environ)
        for key in tuple(runtime_environment):
            upper = key.upper()
            if (
                key in TRUTH_ENVIRONMENT_KEYS
                or "GROUND_TRUTH" in upper
                or "BENCHMARK_TRUTH" in upper
            ):
                runtime_environment.pop(key, None)
        runtime_environment.update(self.environment)
        return self._run(
            [str(value) for value in argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=runtime_environment,
        )

    def _inspect(self, argv: Sequence[str], *, context: str) -> Dict[str, Any]:
        result = self._invoke(argv)
        if result.returncode != 0:
            detail = str(result.stderr or result.stdout or "").strip()
            raise BenchmarkIsolationError(
                f"{context} failed ({result.returncode})" + (f": {detail}" if detail else "")
            )
        return _json_object(str(result.stdout or ""), context=context)

    def preflight(self) -> Dict[str, Any]:
        if self._preflight is not None:
            return dict(self._preflight)
        info_argv = (
            [self.runtime_path, "info", "--format", "json"]
            if self.runtime_family == "podman"
            else [self.runtime_path, "info", "--format", "{{json .}}"]
        )
        info = self._inspect(info_argv, context="OCI runtime info")
        if not _is_rootless_info(self.runtime_family, info):
            raise BenchmarkIsolationError("OCI runtime is not verified rootless")

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
        proxy_labels = _labels(_nested(proxy, "Config", "Labels"))
        proxy_network = _container_networks(proxy).get(self.network_policy.network_name)
        proxy_running = _nested(proxy, "State", "Running") is True
        aliases = []
        if isinstance(proxy_network, Mapping):
            aliases = [str(value).lower() for value in proxy_network.get("Aliases") or []]
        if not proxy_id or not proxy_running or not isinstance(proxy_network, Mapping):
            raise BenchmarkIsolationError(
                "model endpoint proxy is not running on the policy network"
            )
        if proxy_labels.get(_PROXY_LABEL_ROLE) != "model-endpoint-proxy":
            raise BenchmarkIsolationError("model endpoint proxy role is not attested")
        if proxy_labels.get(_PROXY_LABEL_SHA) != self.network_policy.policy_sha256:
            raise BenchmarkIsolationError("model endpoint proxy policy digest does not match")
        if self.network_policy.endpoint_host not in aliases:
            raise BenchmarkIsolationError("model endpoint hostname is not a proxy network alias")
        peers = _network_peers(network)
        if len(peers) != 1 or not any(_identity_matches(proxy_id, peer) for peer in peers):
            raise BenchmarkIsolationError(
                "endpoint-only network must contain exactly the declared proxy before execution"
            )

        self._preflight = {
            "runtime_info_sha256": _canonical_sha256(info),
            "image_inspect_sha256": _canonical_sha256(image_inspect),
            "image_id": image_id,
            "network_inspect_sha256": _canonical_sha256(network),
            "proxy_inspect_sha256": _canonical_sha256(proxy),
            "rootless_verified": True,
            "image_digest_verified": True,
            "network_internal": True,
            "network_policy_sha256": self.network_policy.policy_sha256,
            "network_name": self.network_policy.network_name,
            "endpoint_origin": self.network_policy.endpoint_origin,
            "proxy_container_id": proxy_id,
            "proxy_running": True,
        }
        return dict(self._preflight)

    def _actual_mounts(self, inspect: Mapping[str, Any]) -> list[Dict[str, Any]]:
        expected = {
            "/zscope-input": "scan_input",
            "/zscope-output": "artifact_output",
            "/zscope-cache": "cache",
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
        run_result: subprocess.CompletedProcess[str],
        accepted_returncodes: Sequence[int],
    ) -> Dict[str, Any]:
        inspect = self._inspect(
            [self.runtime_path, "inspect", name], context=f"{phase} container inspect"
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
        }
        actual_sources = {
            (str(row["source"]), str(row["destination"]), bool(row["read_only"])) for row in mounts
        }
        peers = _network_peers(network)
        proxy_id = str(_as_mapping(self._preflight).get("proxy_container_id") or "")
        proxy_current_id = str(proxy.get("Id") or proxy.get("ID") or "")
        proxy_labels = _labels(_nested(proxy, "Config", "Labels"))
        proxy_network = _container_networks(proxy).get(self.network_policy.network_name)
        proxy_aliases = (
            [str(value).lower() for value in proxy_network.get("Aliases") or []]
            if isinstance(proxy_network, Mapping)
            else []
        )
        proxy_verified = bool(
            _identity_matches(proxy_current_id, proxy_id)
            and _nested(proxy, "State", "Running") is True
            and isinstance(proxy_network, Mapping)
            and proxy_labels.get(_PROXY_LABEL_ROLE) == "model-endpoint-proxy"
            and proxy_labels.get(_PROXY_LABEL_SHA) == self.network_policy.policy_sha256
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
        peer_ids_valid = bool(
            len(peers) == 2
            and any(_identity_matches(container_id, peer) for peer in peers)
            and any(_identity_matches(proxy_id, peer) for peer in peers)
        )
        network_mode = str(_nested(inspect, "HostConfig", "NetworkMode") or "")
        if not network_mode:
            network_mode = (
                self.network_policy.network_name
                if self.network_policy.network_name in networks
                else ""
            )
        image_ref = str(_nested(inspect, "Config", "Image") or "")
        container_image_id = str(inspect.get("Image") or inspect.get("ImageID") or "")
        expected_image_id = str(_as_mapping(self._preflight).get("image_id") or "")
        image_verified = bool(
            image_ref and _image_identity_matches(container_image_id, expected_image_id)
        )
        scanner_labels = _labels(_nested(inspect, "Config", "Labels"))
        scanner_labels_verified = bool(
            scanner_labels.get(_PROXY_LABEL_ROLE) == "scanner"
            and scanner_labels.get(_NETWORK_LABEL_SHA) == self.network_policy.policy_sha256
        )
        cap_drop_verified = bool(
            any(str(value).upper() == "ALL" for value in cap_drop)
            or (isinstance(effective_caps, list) and not effective_caps)
        )
        security_verified = bool(
            readonly_rootfs
            and cap_drop_verified
            and any("no-new-privileges" in str(value).lower() for value in security_opt)
        )
        inspect_verified = bool(
            container_id
            and working_dir == "/zscope-input"
            and expected_sources == actual_sources
            and all(row.get("type") in {"bind", ""} for row in mounts)
            and network_mode == self.network_policy.network_name
            and self.network_policy.network_name in networks
            and peer_ids_valid
            and network_contract_verified
            and scanner_labels_verified
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
            "security_opt": list(security_opt) if isinstance(security_opt, list) else [],
            "security_verified": security_verified,
            "scanner_labels_verified": scanner_labels_verified,
            "mounts": mounts,
            "unexpected_mount_count": sum(row["purpose"] == "unexpected" for row in mounts),
            "network_name": network_mode,
            "network_peer_count": len(peers),
            "network_peers_verified": peer_ids_valid,
            "network_internal": network_internal is True,
            "network_contract_verified": network_contract_verified,
            "proxy_verified": proxy_verified,
            "container_inspect_sha256": _canonical_sha256(inspect),
            "proxy_inspect_sha256": _canonical_sha256(proxy),
            "network_inspect_sha256": _canonical_sha256(network),
            "inspect_verified": inspect_verified,
        }

    def execute_phase(
        self,
        phase: str,
        command: Sequence[str],
        *,
        log_path: Path,
        accepted_returncodes: Sequence[int] = (0,),
    ) -> OciPhaseResult:
        import time

        self.preflight()
        if not phase or not command:
            raise BenchmarkIsolationError("OCI phase and command must be non-empty")
        command_text = json.dumps([str(value) for value in command]).lower()
        if "ground_truth" in command_text or "benchmark/" in command_text:
            raise BenchmarkIsolationError("scan command references benchmark answer material")
        safe_phase = _SAFE_NAME_RE.sub("-", phase).strip("-.")[:32] or "phase"
        name = f"zscope-benchmark-{safe_phase}-{uuid.uuid4().hex[:12]}"
        argv = [
            self.runtime_path,
            "run",
            "--name",
            name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--workdir",
            "/zscope-input",
            "--mount",
            f"type=bind,src={self.scan_input},dst=/zscope-input,readonly",
            "--mount",
            f"type=bind,src={self.artifact_output},dst=/zscope-output",
            "--mount",
            f"type=bind,src={self.cache_output},dst=/zscope-cache",
            "--network",
            self.network_policy.network_name,
            "--label",
            "io.zscope.role=scanner",
            "--label",
            f"{_NETWORK_LABEL_SHA}={self.network_policy.policy_sha256}",
        ]
        for key in sorted(key for key in self.environment if key in _PASSTHROUGH_ENVIRONMENT):
            argv.extend(("--env", key))
        argv.extend((self.image, *(str(value) for value in command)))
        started = time.monotonic()
        run_result = self._invoke(argv)
        elapsed = time.monotonic() - started
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            str(run_result.stdout or "") + str(run_result.stderr or ""), encoding="utf-8"
        )
        phase_evidence: Optional[Dict[str, Any]] = None
        inspection_error = ""
        try:
            phase_evidence = self._phase_evidence(
                phase=phase,
                name=name,
                run_result=run_result,
                accepted_returncodes=tuple(int(value) for value in accepted_returncodes),
            )
        except BenchmarkIsolationError as exc:
            inspection_error = str(exc)
        finally:
            cleanup = self._invoke([self.runtime_path, "rm", "--force", name])
        if cleanup.returncode != 0:
            raise BenchmarkIsolationError(f"failed to remove inspected OCI container {name}")
        if inspection_error:
            raise BenchmarkIsolationError(inspection_error)
        assert phase_evidence is not None
        self._phases.append(phase_evidence)
        if phase_evidence.get("inspect_verified") is not True:
            raise BenchmarkIsolationError(f"OCI phase {phase!r} failed execution evidence checks")
        return OciPhaseResult(
            phase=phase,
            seconds=elapsed,
            return_code=int(run_result.returncode),
            evidence=dict(phase_evidence),
        )

    def execution_evidence(self, *, required_phases: Sequence[str] = ()) -> Dict[str, Any]:
        preflight = self.preflight()
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
            "release_capable": phases_verified,
            "truth_mounted": False,
            "repository_mounted": False,
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
    for key, expected in (
        ("mode", "oci"),
        ("available", True),
        ("rootless_verified", True),
        ("image_digest_verified", True),
        ("execution_verified", True),
        ("actual_inspection_collected", True),
        ("release_capable", True),
        ("truth_mounted", False),
        ("repository_mounted", False),
        ("scanner_cwd_isolated", True),
        ("mounts_verified", True),
        ("security_verified", True),
        ("network_restriction_verified", True),
    ):
        if evidence.get(key) != expected:
            errors.append(f"{key} must be {expected!r}")
    if not _PINNED_IMAGE_RE.fullmatch(str(evidence.get("image") or "")):
        errors.append("image must be pinned by a 64-hex sha256 digest")
    if evidence.get("network_mode") != "model-endpoint-only":
        errors.append("network_mode must be 'model-endpoint-only'")
    if not _SHA256_RE.fullmatch(str(evidence.get("network_policy_sha256") or "")):
        errors.append("network policy digest is missing or invalid")
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
        if purpose not in {"scan_input", "artifact_output", "cache"}:
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
        for truth in protected_truth:
            if truth == source or truth.is_relative_to(source):
                errors.append(f"mounts[{index}] contains benchmark truth")
    if not scan_mount_found:
        errors.append("scanner_cwd is not within the sealed scan_input mount")
    for purpose in ("scan_input", "artifact_output", "cache"):
        if purpose not in found_purposes:
            errors.append(f"{purpose} mount evidence is missing")
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
                "scanner_labels_verified",
                "image_verified",
            ):
                if raw.get(field) is not True:
                    errors.append(f"phase_executions[{index}].{field} must be true")
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
