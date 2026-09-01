from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from zscope.benchmarking import isolation as benchmark_isolation
from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    OciNetworkPolicy,
    P6OciCleanupScope,
    RootlessOciExecutor,
    oci_capability,
    require_release_isolation,
    sealed_runtime_source_sha256,
    validate_oci_execution_evidence,
)
from zscope.benchmarking import runner as benchmark_runner
from zscope.benchmarking.provider_runtime import ProviderRuntimeContract


PROXY_ID = "8" * 64
SCANNER_ID = "9" * 64
CANARY_ID = "7" * 64
PROXY_UPSTREAMS_SHA256 = "7" * 64
PROXY_EGRESS_NETWORK = "zscope-model-egress"
PROXY_ARGS = [
    "/opt/zscope/p6_tcp_relay.py",
    "--listen-port",
    "443",
    "--upstream",
    "203.0.113.10:443",
]
IMAGE_LABELS = {
    "org.opencontainers.image.base.digest": "sha256:" + "b" * 64,
    "org.opencontainers.image.revision": "c" * 40,
    "io.zscope.p6-runtime-lock-sha256": "d" * 64,
    "io.zscope.p6-containerfile-sha256": "e" * 64,
}
PROXY_TMPFS = "rw,noexec,nosuid,nodev,size=16m"


def _canonical_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _retained_image_environment(rows: list[str]) -> dict[str, str]:
    values = dict(row.split("=", 1) for row in rows)
    return {
        key: value
        for key, value in values.items()
        if not any(marker in key.upper() for marker in ("KEY", "SECRET", "TOKEN", "PASSWORD"))
    }


class FakeOciRuntime:
    def __init__(
        self,
        *,
        runtime: str,
        image: str,
        scan_input: Path,
        output: Path,
        cache: Path,
        relay_source: Path,
        runtime_source: Path | None = None,
        environment: dict[str, str],
        provider_contract: ProviderRuntimeContract | None = None,
        rootless: bool = True,
        digest_matches: bool = True,
        internal_network: bool = True,
        tamper_mounts: bool = False,
        extra_network_peer: bool = False,
        podman_v4_inspect: bool = False,
        partial_cap_drop: bool = False,
        extra_network_attachment: bool = False,
        proxy_exposes_secret_environment: bool = False,
        image_environment: list[str] | None = None,
        drift_proxy_attestation_after_run: bool = False,
        drift_cleanup_scope_after_run: bool = False,
        replace_proxy_before_preflight: bool = False,
        container_cleanup_fails: bool = False,
        canary_cleanup_fails: bool = False,
        canary_run_fails: bool = False,
        short_network_ids: bool = False,
        replace_scanner_after_run: bool = False,
        run_stdout: str = "",
        run_stderr: str = "",
        raise_on_run: bool = False,
        interrupt_on_run: str = "",
    ) -> None:
        self.runtime = runtime
        self.image = image
        self.scan_input = scan_input.resolve()
        self.output = output.resolve()
        self.cache = cache.resolve()
        self.relay_source = relay_source.resolve()
        relay_metadata = self.relay_source.stat()
        relay_content = self.relay_source.read_bytes()
        self.relay_sha256 = hashlib.sha256(relay_content).hexdigest()
        self.relay_projection_sha256 = _canonical_sha256(
            {
                "device": relay_metadata.st_dev,
                "inode": relay_metadata.st_ino,
                "mode": relay_metadata.st_mode & 0o7777,
                "sha256": self.relay_sha256,
                "size": relay_metadata.st_size,
                "uid": relay_metadata.st_uid,
            }
        )
        self.runtime_source = runtime_source.resolve() if runtime_source is not None else None
        self.policy = (
            OciNetworkPolicy.from_provider_contract(environment, provider_contract)
            if provider_contract is not None
            else OciNetworkPolicy.from_environment(environment)
        )
        self.rootless = rootless
        self.digest_matches = digest_matches
        self.internal_network = internal_network
        self.tamper_mounts = tamper_mounts
        self.extra_network_peer = extra_network_peer
        self.podman_v4_inspect = podman_v4_inspect
        self.partial_cap_drop = partial_cap_drop
        self.extra_network_attachment = extra_network_attachment
        self.proxy_exposes_secret_environment = proxy_exposes_secret_environment
        self.image_environment = list(image_environment or [])
        self.drift_proxy_attestation_after_run = drift_proxy_attestation_after_run
        self.drift_cleanup_scope_after_run = drift_cleanup_scope_after_run
        self.replace_proxy_before_preflight = replace_proxy_before_preflight
        self.container_cleanup_fails = container_cleanup_fails
        self.canary_cleanup_fails = canary_cleanup_fails
        self.canary_run_fails = canary_run_fails
        self.short_network_ids = short_network_ids
        self.replace_scanner_after_run = replace_scanner_after_run
        self.run_stdout = run_stdout
        self.run_stderr = run_stderr
        self.raise_on_run = raise_on_run
        self.interrupt_on_run = interrupt_on_run
        self.scanner_name = ""
        self.run_argv: list[str] = []
        self.run_pass_fds: tuple[int, ...] = ()
        self.canary_argv: list[str] = []
        self.canary_pass_fds: tuple[int, ...] = ()
        self.scanner_environment: list[str] = []
        self.scanner_labels: dict[str, str] = {}
        self.scanner_secret_mounts: list[dict[str, Any]] = []
        self.runtime_environments: list[dict[str, str]] = []
        self.runtime_invocations: list[tuple[list[str], dict[str, str]]] = []
        self.removed_names: list[str] = []

    @staticmethod
    def _result(argv: list[str], value: Any = None, returncode: int = 0, *, stderr: str = ""):
        stdout = "" if value is None else json.dumps(value)
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    def __call__(self, argv: list[str], **kwargs: Any):
        command = [str(value) for value in argv]
        runtime_environment = dict(kwargs.get("env") or {})
        self.runtime_environments.append(runtime_environment)
        self.runtime_invocations.append((command, runtime_environment))
        if command[1:3] == ["info", "--format"]:
            if self.runtime == "podman":
                return self._result(command, {"host": {"security": {"rootless": self.rootless}}})
            options = ["name=rootless"] if self.rootless else ["name=seccomp"]
            return self._result(command, {"SecurityOptions": options})
        if command[1:3] == ["image", "inspect"]:
            digest = self.image.rsplit("@", 1)[1] if self.digest_matches else "sha256:" + "b" * 64
            return self._result(
                command,
                [
                    {
                        "Id": digest,
                        "RepoDigests": ["repo@" + digest],
                        "Config": {
                            "Env": self.image_environment,
                            "Labels": dict(IMAGE_LABELS),
                        },
                    }
                ],
            )
        if command[1:] == ["run", "--help"]:
            return subprocess.CompletedProcess(
                command, 0, "  --preserve-fds uint   preserve descriptors\n", ""
            )
        if self.runtime == "podman" and command[1:3] == ["ps", "--all"]:
            assert command[3:6] == [
                "--no-trunc",
                "--filter",
                f"network={self.policy.network_name}",
            ]
            proxy_peer_id = PROXY_ID[:12] if self.short_network_ids else PROXY_ID
            rows: list[dict[str, Any]] = [
                {"Id": proxy_peer_id, "Networks": [self.policy.network_name]}
            ]
            if self.scanner_name:
                rows.append({"Id": SCANNER_ID, "Networks": [self.policy.network_name]})
            if self.extra_network_peer:
                rows.append({"Id": "a" * 64, "Networks": [self.policy.network_name]})
            return self._result(command, rows)
        if command[1:3] == ["network", "inspect"]:
            peers: dict[str, Any] = {PROXY_ID: {"Name": "model-proxy"}}
            if self.scanner_name:
                peers[SCANNER_ID] = {"Name": self.scanner_name}
            if self.extra_network_peer:
                peers["a" * 64] = {"Name": "unexpected"}
            network = {
                "Name": self.policy.network_name,
                "Internal": self.internal_network,
                "Labels": {
                    "io.zscope.network-policy": "model-endpoint-only",
                    "io.zscope.network-policy-sha256": self.policy.policy_sha256,
                },
            }
            if self.runtime != "podman":
                network["Containers"] = peers
            return self._result(
                command,
                [network],
            )
        if command[1] == "inspect" and command[2] == self.policy.proxy_container:
            drifted = self.drift_proxy_attestation_after_run and bool(self.scanner_name)
            proxy_id = "5" * 64 if self.replace_proxy_before_preflight else PROXY_ID
            return self._result(
                command,
                [
                    {
                        "Id": proxy_id,
                        "Name": "/model-proxy",
                        "Image": self.image.rsplit("@", 1)[1],
                        "ImageName": self.image,
                        "Path": "python3",
                        "Args": list(PROXY_ARGS),
                        "Config": {
                            "Labels": {
                                **IMAGE_LABELS,
                                "io.zscope.role": (
                                    "unexpected-proxy" if drifted else "model-endpoint-proxy"
                                ),
                                "io.zscope.network-policy-sha256": (
                                    "e" * 64 if drifted else self.policy.policy_sha256
                                ),
                                "io.zscope.relay-sha256": self.relay_sha256,
                                "io.zscope.relay-projection-sha256": (self.relay_projection_sha256),
                                "io.zscope.upstreams-sha256": PROXY_UPSTREAMS_SHA256,
                            },
                            "Env": (
                                ["Z_SCOPE_API_KEY=proxy-secret"]
                                if self.proxy_exposes_secret_environment
                                else [
                                    f"{key}={value}"
                                    for key, value in _retained_image_environment(
                                        self.image_environment
                                    ).items()
                                ]
                            ),
                            "Image": self.image,
                            "Entrypoint": None,
                            "Cmd": None,
                            "User": "65532:65532",
                        },
                        "HostConfig": {
                            "ReadonlyRootfs": True,
                            "Privileged": False,
                            "CapDrop": ["ALL"],
                            "CapAdd": ["NET_BIND_SERVICE"],
                            "SecurityOpt": ["no-new-privileges"],
                            "PidsLimit": 64,
                            "LogConfig": {"Type": "none", "Config": {}},
                            "Tmpfs": {"/tmp": PROXY_TMPFS},
                        },
                        "State": {"Running": True},
                        "Mounts": [
                            {
                                "Type": "bind",
                                "Source": str(self.relay_source),
                                "Destination": "/opt/zscope/p6_tcp_relay.py",
                                "RW": False,
                            },
                            {
                                "Type": "tmpfs",
                                "Source": "tmpfs",
                                "Destination": "/tmp",
                                "RW": True,
                            },
                        ],
                        "NetworkSettings": {
                            "Networks": {
                                self.policy.network_name: {"Aliases": [self.policy.endpoint_host]},
                                PROXY_EGRESS_NETWORK: {"Aliases": ["model-proxy"]},
                            }
                        },
                    }
                ],
            )
        if command[1] == "run":
            if "--network=none" in command:
                self.canary_argv = command
                self.canary_pass_fds = tuple(kwargs.get("pass_fds") or ())
                cidfile = Path(command[command.index("--cidfile") + 1])
                cidfile.write_text(CANARY_ID + "\n", encoding="ascii")
                return subprocess.CompletedProcess(
                    command, 1 if self.canary_run_fails else 0, "", ""
                )
            self.scanner_name = command[command.index("--name") + 1]
            self.run_argv = command
            self.run_pass_fds = tuple(kwargs.get("pass_fds") or ())
            cidfile = Path(command[command.index("--cidfile") + 1])
            cidfile.write_text(SCANNER_ID + "\n", encoding="ascii")
            runtime_environment = dict(kwargs.get("env") or {})
            self.scanner_environment = []
            self.scanner_labels = {}
            self.scanner_secret_mounts = []
            for index, value in enumerate(command[:-1]):
                specification = command[index + 1]
                if value == "--env":
                    if "=" in specification:
                        self.scanner_environment.append(specification)
                    else:
                        self.scanner_environment.append(
                            f"{specification}={runtime_environment.get(specification, '')}"
                        )
                elif value == "--label" and "=" in specification:
                    key, item = specification.split("=", 1)
                    self.scanner_labels[key] = item
                elif value == "--mount" and "dst=/run/zscope-provider-secrets/" in specification:
                    parts = {
                        item.split("=", 1)[0]: item.split("=", 1)[1]
                        for item in specification.split(",")
                        if "=" in item
                    }
                    self.scanner_secret_mounts.append(
                        {
                            "Type": "bind",
                            "Source": parts["src"],
                            "Destination": parts["dst"],
                            "RW": False,
                        }
                    )
            if self.raise_on_run:
                raise RuntimeError("runtime failure containing top-secret")
            if self.interrupt_on_run == "keyboard":
                raise KeyboardInterrupt()
            if self.interrupt_on_run == "sigterm":
                handler = signal.getsignal(signal.SIGTERM)
                assert callable(handler)
                handler(signal.SIGTERM, None)
            return subprocess.CompletedProcess(command, 0, self.run_stdout, self.run_stderr)
        if command[1] == "inspect" and command[2] in {self.scanner_name, SCANNER_ID}:
            input_source = self.output if self.tamper_mounts else self.scan_input
            return self._result(
                command,
                [
                    {
                        "Id": "4" * 64 if self.replace_scanner_after_run else SCANNER_ID,
                        "Name": "/" + self.scanner_name,
                        "Image": self.image.rsplit("@", 1)[1],
                        "Config": {
                            "WorkingDir": "/zscope-input",
                            "Image": self.image,
                            "Labels": {
                                "io.zscope.role": "scanner",
                                "io.zscope.network-policy-sha256": self.policy.policy_sha256,
                                **self.scanner_labels,
                                **(
                                    {"io.zscope.p6-attempt-id": "p6-999-1"}
                                    if self.drift_cleanup_scope_after_run
                                    else {}
                                ),
                            },
                            "Env": list(self.scanner_environment),
                        },
                        "HostConfig": {
                            "ReadonlyRootfs": True,
                            "CapDrop": (
                                ["CAP_CHOWN"]
                                if self.partial_cap_drop
                                else (
                                    [
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
                                    ]
                                    if self.podman_v4_inspect
                                    else ["ALL"]
                                )
                            ),
                            "SecurityOpt": ["no-new-privileges:true"],
                            "LogConfig": {"Type": "none", "Config": {}},
                            "NetworkMode": (
                                "bridge" if self.podman_v4_inspect else self.policy.network_name
                            ),
                        },
                        "State": {"ExitCode": 0},
                        "Mounts": [
                            {
                                "Type": "bind",
                                "Source": str(input_source),
                                "Destination": "/zscope-input",
                                "RW": False,
                            },
                            {
                                "Type": "bind",
                                "Source": str(self.output),
                                "Destination": "/zscope-output",
                                "RW": True,
                            },
                            {
                                "Type": "bind",
                                "Source": str(self.cache),
                                "Destination": "/zscope-cache",
                                "RW": True,
                            },
                            *(
                                [
                                    {
                                        "Type": "bind",
                                        "Source": str(self.runtime_source),
                                        "Destination": "/zscope-runtime/zscope",
                                        "RW": False,
                                    }
                                ]
                                if self.runtime_source is not None
                                else []
                            ),
                            *self.scanner_secret_mounts,
                        ],
                        "NetworkSettings": {
                            "Networks": {
                                self.policy.network_name: {"Aliases": [self.scanner_name]},
                                **(
                                    {"unexpected-network": {"Aliases": [self.scanner_name]}}
                                    if self.extra_network_attachment
                                    else {}
                                ),
                            }
                        },
                    }
                ],
            )
        if command[1:3] == ["rm", "--force"]:
            if command[3] == CANARY_ID:
                if self.canary_cleanup_fails:
                    return self._result(command, returncode=1)
                return self._result(command)
            if self.container_cleanup_fails:
                return self._result(command, returncode=1)
            self.removed_names.append(command[3])
            self.scanner_name = ""
            return self._result(command)
        raise AssertionError(f"unexpected OCI command: {command}")


def _write_proxy_attestation(
    path: Path,
    *,
    image: str,
    policy: OciNetworkPolicy,
    provider_contract: ProviderRuntimeContract,
    relay_source: Path,
    image_environment: list[str],
) -> str:
    relay_metadata = relay_source.stat()
    relay_content = relay_source.read_bytes()
    relay_sha256 = hashlib.sha256(relay_content).hexdigest()
    relay_projection_sha256 = _canonical_sha256(
        {
            "device": relay_metadata.st_dev,
            "inode": relay_metadata.st_ino,
            "mode": relay_metadata.st_mode & 0o7777,
            "sha256": relay_sha256,
            "size": relay_metadata.st_size,
            "uid": relay_metadata.st_uid,
        }
    )
    image_id = image.rsplit("@", 1)[1]
    image_digest = image.rsplit("@", 1)[1]
    network_names = sorted([policy.network_name, PROXY_EGRESS_NETWORK])
    network_aliases_sha256 = _canonical_sha256(
        {
            "network_names": network_names,
            "aliases": {
                policy.network_name: [policy.endpoint_host],
                PROXY_EGRESS_NETWORK: ["model-proxy"],
            },
        }
    )
    command_projection_sha256 = _canonical_sha256({"path": "python3", "args": PROXY_ARGS})
    retained_environment = _retained_image_environment(image_environment)
    unset_environment_keys = sorted(
        set(dict(row.split("=", 1) for row in image_environment)) - set(retained_environment)
    )
    environment_projection_sha256 = _canonical_sha256({"environment": retained_environment})
    security_projection_sha256 = _canonical_sha256(
        {
            "user": "65532:65532",
            "read_only_rootfs": True,
            "privileged": False,
            "security_opt": ["no-new-privileges"],
            "pids_limit": 64,
            "cap_drop": ["ALL"],
            "cap_add": ["NET_BIND_SERVICE"],
            "tmpfs": {"/tmp": sorted(PROXY_TMPFS.split(","))},
            "relay_mount": {
                "destination": "/opt/zscope/p6_tcp_relay.py",
                "read_only": True,
                "relay_projection_sha256": relay_projection_sha256,
            },
        }
    )
    log_driver_projection_sha256 = _canonical_sha256({"Type": "none", "Config": {}})
    proxy_projection_sha256 = _canonical_sha256(
        {
            "proxy_container": "model-proxy",
            "proxy_container_id": PROXY_ID,
            "image_ref": image,
            "image_id": image_id,
            "endpoint_host": policy.endpoint_host,
            "network_names": network_names,
            "network_aliases_sha256": network_aliases_sha256,
            "command_projection_sha256": command_projection_sha256,
            "expected_environment_sha256": environment_projection_sha256,
            "security_projection_sha256": security_projection_sha256,
            "log_driver_projection_sha256": log_driver_projection_sha256,
        }
    )
    image_projection_sha256 = _canonical_sha256(
        {
            "image_ref": image,
            "image_id": image_id,
            "image_digest": image_digest,
            "labels": IMAGE_LABELS,
            "environment": retained_environment,
            "unset_environment_keys": unset_environment_keys,
        }
    )
    candidate = "2" * 40
    value: dict[str, Any] = {
        "schema_version": "zscope.p6-expected-proxy-attestation.v2",
        "workflow_run_id": "12345",
        "workflow_run_attempt": 2,
        "attempt_id": "p6-12345-2",
        "control_plane_commit": "1" * 40,
        "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "candidate_git_sha": candidate,
        "candidate_git_tree": "3" * 40,
        "toolchain_evidence_sha256": "4" * 64,
        "toolchain_evidence_content_sha256": "f" * 64,
        "image_provenance_sha256": "5" * 64,
        "image_provenance_content_sha256": "1" * 64,
        "proxy_provision_sha256": "6" * 64,
        "proxy_provision_content_sha256": "2" * 64,
        "image_ref": image,
        "image_id": image_id,
        "provider_identity_sha256": provider_contract.identity_sha256,
        "network_name": policy.network_name,
        "egress_network_name": PROXY_EGRESS_NETWORK,
        "network_names": network_names,
        "network_aliases_sha256": network_aliases_sha256,
        "proxy_container": "model-proxy",
        "proxy_container_id": PROXY_ID,
        "endpoint_origin": policy.endpoint_origin,
        "endpoint_host": policy.endpoint_host,
        "network_policy_sha256": policy.policy_sha256,
        "relay_sha256": relay_sha256,
        "relay_projection_sha256": relay_projection_sha256,
        "upstreams_sha256": PROXY_UPSTREAMS_SHA256,
        "upstream_count": 1,
        "command_projection_sha256": command_projection_sha256,
        "expected_environment_sha256": environment_projection_sha256,
        "credential_environment_keys": [],
        "security_projection_sha256": security_projection_sha256,
        "log_driver_projection_sha256": log_driver_projection_sha256,
        "image_inspect_projection_sha256": image_projection_sha256,
        "proxy_inspect_projection_sha256": proxy_projection_sha256,
        "formal_evidence": False,
        "release_eligible": False,
    }
    value["content_sha256"] = _canonical_sha256(value)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bootstrap_attestation_from_final(path: Path) -> dict[str, Any]:
    final = json.loads(path.read_text(encoding="utf-8"))
    value: dict[str, Any] = {
        "schema_version": "zscope.p6-bootstrap-proxy-attestation.v1",
        "workflow_run_id": final["workflow_run_id"],
        "workflow_run_attempt": final["workflow_run_attempt"],
        "attempt_id": final["attempt_id"],
        "repository": "example/zscope",
        **{
            key: final[key]
            for key in (
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
            )
        },
        "bootstrap_preflight_only": True,
        "formal_evidence": False,
        "release_eligible": False,
    }
    value["content_sha256"] = _canonical_sha256(value)
    return value


def _anonymous_test_fd(name: str) -> int:
    memfd_create = getattr(os, "memfd_create", None)
    if callable(memfd_create):
        return int(
            memfd_create(
                name,
                int(getattr(os, "MFD_CLOEXEC", 0)) | int(getattr(os, "MFD_ALLOW_SEALING", 0)),
            )
        )
    stream = tempfile.TemporaryFile()
    descriptor = os.dup(stream.fileno())
    stream.close()
    return descriptor


def _executor(
    tmp_path: Path,
    *,
    runtime: str = "podman",
    with_runtime_source: bool = False,
    p6_cleanup_scope: bool = False,
    bootstrap_preflight: bool = False,
    **fake_options: Any,
) -> tuple[RootlessOciExecutor, FakeOciRuntime, Path]:
    scan_input = tmp_path / "sealed"
    output = tmp_path / "output"
    cache = tmp_path / "cache"
    for path in (scan_input, output, cache):
        path.mkdir()
    relay_source = tmp_path / "p6_tcp_relay.py"
    relay_source.write_text("# sealed relay\n", encoding="utf-8")
    runtime_source = tmp_path / "runtime-source" if with_runtime_source else None
    if runtime_source is not None:
        runtime_source.mkdir()
        (runtime_source / "__init__.py").write_text("\n", encoding="utf-8")
        (runtime_source / "runtime_defaults.yaml").write_text("version: 1\n", encoding="utf-8")
    (scan_input / "demo.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    environment = {
        "Z_SCOPE_API_KEY": "top-secret",
        "Z_SCOPE_LLM_BASE_URL": "https://models.internal/v1",
        "Z_SCOPE_LLM_MODEL": "glm-5.1",
        "Z_SCOPE_BENCHMARK_OCI_NETWORK": "zscope-model-only",
        "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": "model-proxy",
        **(
            {
                "GITHUB_REPOSITORY": "example/zscope",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "2",
                "P6_ATTEMPT_ID": "p6-12345-2",
            }
            if p6_cleanup_scope
            else {}
        ),
    }
    image = "registry.example/zscope@sha256:" + "a" * 64
    provider_contract = ProviderRuntimeContract(
        base_url="https://models.internal/v1",
        model="glm-5.1",
        response_model="glm-5.1",
        config_sha256="c" * 64,
        required_environment_keys=("Z_SCOPE_API_KEY",),
        identity_sha256="d" * 64,
    )
    policy = OciNetworkPolicy.from_provider_contract(environment, provider_contract)
    attestation_path = (tmp_path / "proxy-attestation.json").absolute()
    attestation_sha256 = _write_proxy_attestation(
        attestation_path,
        image=image,
        policy=policy,
        provider_contract=provider_contract,
        relay_source=relay_source,
        image_environment=list(fake_options.get("image_environment") or []),
    )
    bootstrap_attestation = None
    if bootstrap_preflight:
        if not p6_cleanup_scope:
            raise AssertionError("bootstrap test executor requires a P6 cleanup scope")
        bootstrap_attestation = _bootstrap_attestation_from_final(attestation_path)
    else:
        environment.update(
            {
                "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE": str(attestation_path),
                "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256": attestation_sha256,
            }
        )
    fake = FakeOciRuntime(
        runtime=runtime,
        image=image,
        scan_input=scan_input,
        output=output,
        cache=cache,
        relay_source=relay_source,
        runtime_source=runtime_source,
        environment=environment,
        provider_contract=provider_contract,
        **fake_options,
    )
    executor = RootlessOciExecutor(
        runtime=runtime,
        image=image,
        scan_input=scan_input,
        artifact_output=output,
        cache_output=cache,
        environment=environment,
        provider_contract=provider_contract,
        runtime_source=runtime_source,
        process_runner=fake,
        which=lambda _: f"/usr/bin/{runtime}",
        secret_fd_factory=_anonymous_test_fd,
        bootstrap_expected_proxy_attestation=bootstrap_attestation,
    )
    return executor, fake, scan_input


def test_rootless_executor_collects_runtime_inspection_evidence(tmp_path: Path) -> None:
    executor, fake, scan_input = _executor(tmp_path, runtime="podman")

    result = executor.execute_phase(
        "scan",
        ("python3", "-m", "zscope.cli.cli", "--verbose"),
        log_path=tmp_path / "scan.log",
        accepted_returncodes=(0, 1),
    )
    evidence = executor.execution_evidence(required_phases=("scan",))

    assert result.return_code == 0
    assert evidence["rootless_verified"] is True
    assert evidence["image_digest_verified"] is True
    assert evidence["actual_inspection_collected"] is True
    assert evidence["network_restriction_verified"] is True
    assert evidence["provider_identity_sha256"] == "d" * 64
    assert len(evidence["network_membership_sha256"]) == 64
    assert evidence["phase_executions"][0]["working_dir"] == "/zscope-input"
    assert {row["purpose"] for row in evidence["mounts"]} == {
        "scan_input",
        "artifact_output",
        "cache",
    }
    assert (
        next(row for row in evidence["mounts"] if row["purpose"] == "scan_input")["read_only"]
        is True
    )
    assert "top-secret" not in fake.run_argv
    assert [
        fake.run_argv[index + 1]
        for index, value in enumerate(fake.run_argv[:-1])
        if value == "--env"
    ] == []
    assert "--preserve-fds=1" in fake.run_argv
    assert "--cidfile" in fake.run_argv
    assert 3 in fake.run_pass_fds
    assert any("/proc/self/fd/3" in value for value in fake.run_argv)
    assert result.evidence["scanner_provider_environment_verified"] is True
    assert result.evidence["scanner_provider_environment_keys"] == ["Z_SCOPE_API_KEY"]
    assert result.evidence["cancellation_cleanup_guard_verified"] is True
    assert result.evidence["stdout_persisted"] is False
    assert result.evidence["stderr_persisted"] is False
    assert len(result.evidence["directory_binding_sha256"]) == 64
    assert all("Z_SCOPE_API_KEY" not in item for item in fake.runtime_environments)
    assert "Z_SCOPE_API_KEY" not in executor.environment
    assert executor._provider_environment == {}
    assert "top-secret" not in json.dumps(evidence)
    assert "Z_SCOPE_LLM_BASE_URL" not in fake.run_argv
    assert "Z_SCOPE_LLM_MODEL" not in fake.run_argv
    assert fake.removed_names == [SCANNER_ID]
    if os.name == "posix":
        assert any("src=/proc/self/fd/" in value for value in fake.run_argv)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    truth = checkout / "benchmark" / "ground_truth.json"
    truth.parent.mkdir()
    truth.write_text("{}", encoding="utf-8")
    require_release_isolation(
        required=True,
        capability=evidence,
        repository_checkout=checkout,
        truth_paths=(truth,),
    )
    assert scan_input.is_dir()


def test_preflight_proves_anonymous_descriptor_with_a_zero_secret_canary(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path)

    evidence = executor.preflight()

    assert evidence["preserve_fds_verified"] is True
    assert evidence["preserve_fds_canary_verified"] is True
    assert len(evidence["preserve_fds_canary_sha256"]) == 64
    assert "--network=none" in fake.canary_argv
    assert "--log-driver=none" in fake.canary_argv
    assert "--preserve-fds=1" in fake.canary_argv
    assert "--cidfile" in fake.canary_argv
    assert fake.canary_pass_fds == (3,)
    assert any(
        command[1:4] == ["rm", "--force", CANARY_ID]
        for command, _environment in fake.runtime_invocations
    )
    serialized = json.dumps(fake.canary_argv)
    assert "top-secret" not in serialized
    assert "Z_SCOPE_API_KEY" not in serialized
    assert all("Z_SCOPE_API_KEY" not in row for row in fake.runtime_environments)


def test_preflight_fails_closed_when_descriptor_canary_cleanup_fails(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path, canary_cleanup_fails=True)

    with pytest.raises(BenchmarkIsolationError, match="descriptor canary failed"):
        executor.preflight()

    assert not fake.run_argv
    assert executor._provider_environment == {}


def test_preflight_does_not_trust_help_when_descriptor_canary_fails(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path, canary_run_fails=True)

    with pytest.raises(BenchmarkIsolationError, match="descriptor canary failed"):
        executor.preflight()

    assert fake.canary_argv
    assert fake.canary_pass_fds == (3,)
    assert not fake.run_argv
    assert executor._provider_environment == {}


def test_provider_handoff_fails_before_secret_creation_after_proxy_replacement(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path)
    executor.preflight()
    fake.replace_proxy_before_preflight = True

    with pytest.raises(BenchmarkIsolationError, match="immutable identity"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert not fake.run_argv
    assert fake.run_pass_fds == ()
    assert executor._provider_environment == {}


def test_provider_phase_rejects_scan_input_path_replacement_before_handoff(
    tmp_path: Path,
) -> None:
    executor, fake, scan_input = _executor(tmp_path)
    original = tmp_path / "sealed-original"
    scan_input.rename(original)
    scan_input.mkdir()
    (scan_input / "ground_truth.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(BenchmarkIsolationError, match="scan_input binding identity changed"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert not fake.run_argv
    assert executor._provider_environment == {}


def test_provider_phase_mounts_stable_scan_directory_across_swap_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix":
        pytest.skip("stable directory descriptor mounts are POSIX-only")
    executor, fake, scan_input = _executor(tmp_path)
    replacement = tmp_path / "malicious-scan-input"
    replacement.mkdir()
    (replacement / "ground_truth.json").write_text("{}\n", encoding="utf-8")
    displaced = tmp_path / "sealed-displaced"
    original_call = type(fake).__call__
    stable_source_verified = False

    def racing_call(self: FakeOciRuntime, argv: list[str], **kwargs: Any) -> Any:
        nonlocal stable_source_verified
        command = [str(value) for value in argv]
        scanner_run = (
            len(command) > 1
            and command[1] == "run"
            and "--name" in command
            and "--mount" in command
            and "--network=none" not in command
        )
        if not scanner_run:
            return original_call(self, argv, **kwargs)
        scan_input.rename(displaced)
        replacement.rename(scan_input)
        try:
            mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/zscope-input" in command[index + 1]
            )
            source = Path(
                next(item.split("=", 1)[1] for item in mount.split(",") if item.startswith("src="))
            )
            stable_source_verified = bool(
                source != scan_input
                and (source / "demo.c").is_file()
                and not (source / "ground_truth.json").exists()
                and source.stat().st_ino == displaced.stat().st_ino
            )
            return original_call(self, argv, **kwargs)
        finally:
            scan_input.rename(replacement)
            displaced.rename(scan_input)

    monkeypatch.setattr(type(fake), "__call__", racing_call)

    result = executor.execute_phase(
        "scan",
        ("zscope",),
        log_path=tmp_path / "scan.log",
    )

    assert result.evidence["inspect_verified"] is True
    assert stable_source_verified is True
    assert (replacement / "ground_truth.json").is_file()


@pytest.mark.parametrize("attribute", ["artifact_output", "cache_output"])
def test_provider_phase_rejects_mutable_mount_directory_replacement(
    tmp_path: Path,
    attribute: str,
) -> None:
    executor, fake, _ = _executor(tmp_path)
    target = Path(getattr(executor, attribute))
    original = target.with_name(target.name + "-original")
    target.rename(original)
    target.mkdir()

    with pytest.raises(BenchmarkIsolationError, match="binding identity changed"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert not fake.run_argv
    assert executor._provider_environment == {}


def test_provider_phase_fails_closed_when_scanner_cleanup_fails(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path, container_cleanup_fails=True)

    with pytest.raises(BenchmarkIsolationError, match="failed to remove inspected"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert fake.run_argv
    assert 3 in fake.run_pass_fds
    assert executor._provider_environment == {}


def test_provider_phase_rejects_same_name_scanner_replacement_and_cleans_exact_id(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path, replace_scanner_after_run=True)

    with pytest.raises(BenchmarkIsolationError, match="execution evidence"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert fake.removed_names == [SCANNER_ID]
    inspect_commands = [
        command
        for command, _environment in fake.runtime_invocations
        if command[1:2] == ["inspect"] and command[2] == SCANNER_ID
    ]
    assert inspect_commands
    assert executor._provider_environment == {}


def test_bootstrap_executor_is_credential_free_preflight_and_non_release(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(
        tmp_path,
        runtime="podman",
        p6_cleanup_scope=True,
        bootstrap_preflight=True,
    )

    result = executor.execute_phase(
        "preflight",
        ("python3", "-c", "raise SystemExit(0)"),
        log_path=tmp_path / "preflight.log",
        provider_credentials=False,
    )
    evidence = executor.execution_evidence(required_phases=("preflight",))

    assert result.return_code == 0
    assert evidence["bootstrap_preflight_only"] is True
    assert evidence["release_capable"] is False
    assert evidence["phase_executions"][0]["scanner_provider_environment_keys"] == []
    assert validate_oci_execution_evidence(evidence, require_release_capable=False) == []
    assert "top-secret" not in json.dumps(fake.runtime_invocations)
    assert fake.canary_argv == []


@pytest.mark.parametrize(
    ("phase", "provider_credentials"),
    (("scan", False), ("preflight", True)),
)
def test_bootstrap_executor_rejects_scan_or_provider_credentials_before_runtime(
    tmp_path: Path,
    phase: str,
    provider_credentials: bool,
) -> None:
    executor, fake, _ = _executor(
        tmp_path,
        runtime="podman",
        p6_cleanup_scope=True,
        bootstrap_preflight=True,
    )

    with pytest.raises(BenchmarkIsolationError, match="credential-free preflight"):
        executor.execute_phase(
            phase,
            ("python3", "-c", "raise SystemExit(0)"),
            log_path=tmp_path / f"{phase}.log",
            provider_credentials=provider_credentials,
        )

    assert fake.runtime_invocations == []


def test_preflight_rejects_truncated_runtime_container_identity(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path, short_network_ids=True)

    with pytest.raises(BenchmarkIsolationError, match="unbound or unidentified"):
        executor.preflight()

    assert not fake.canary_argv
    assert not fake.run_argv


def test_attestation_file_is_revalidated_before_any_runtime_call(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path)
    assert executor.expected_proxy_attestation_path is not None
    executor.expected_proxy_attestation_path.write_bytes(
        executor.expected_proxy_attestation_path.read_bytes() + b" "
    )

    with pytest.raises(BenchmarkIsolationError, match="expected proxy attestation is invalid"):
        executor.preflight()

    assert fake.runtime_invocations == []
    assert executor._provider_environment == {}


def test_provider_phase_rejects_docker_without_anonymous_fd_handoff(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path, runtime="docker")

    with pytest.raises(BenchmarkIsolationError, match="descriptor preservation"):
        executor.preflight()

    assert not fake.run_argv


def test_p6_executor_binds_exact_orphan_cleanup_labels(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path, p6_cleanup_scope=True)

    result = executor.execute_phase(
        "scan",
        ("python3", "-m", "zscope.cli.cli", "--verbose"),
        log_path=tmp_path / "scan.log",
    )
    evidence = executor.execution_evidence(required_phases=("scan",))

    labels = {
        fake.run_argv[index + 1]
        for index, value in enumerate(fake.run_argv[:-1])
        if value == "--label"
    }
    assert "io.zscope.p6-cleanup-contract=zscope.p6-oci-cleanup.v1" in labels
    assert "io.zscope.p6-concurrency-group=p6-pilot-validation" in labels
    assert "io.zscope.p6-repository=example/zscope" in labels
    assert "io.zscope.p6-workflow-run-id=12345" in labels
    assert "io.zscope.p6-workflow-run-attempt=2" in labels
    assert "io.zscope.p6-attempt-id=p6-12345-2" in labels
    assert "io.zscope.p6-phase=scan" in labels
    assert result.evidence["p6_cleanup_scope_verified"] is True
    assert result.evidence["p6_workflow_run_id"] == "12345"
    assert result.evidence["p6_workflow_run_attempt"] == 2
    assert result.evidence["p6_attempt_id"] == "p6-12345-2"
    assert result.evidence["p6_repository"] == "example/zscope"
    assert result.evidence["p6_concurrency_group"] == "p6-pilot-validation"
    assert result.evidence["p6_phase"] == "scan"
    require_release_isolation(required=True, capability=evidence)


def test_p6_executor_rejects_drifted_orphan_cleanup_labels(tmp_path: Path) -> None:
    executor, fake, _ = _executor(
        tmp_path,
        p6_cleanup_scope=True,
        drift_cleanup_scope_after_run=True,
    )

    with pytest.raises(BenchmarkIsolationError, match="execution evidence checks"):
        executor.execute_phase(
            "scan",
            ("python3", "-m", "zscope.cli.cli", "--verbose"),
            log_path=tmp_path / "scan.log",
        )

    assert fake.removed_names


def test_p6_executor_rejects_partial_or_malformed_cleanup_scope() -> None:
    with pytest.raises(BenchmarkIsolationError, match="cleanup scope"):
        P6OciCleanupScope.from_environment(
            {
                "GITHUB_REPOSITORY": "example/zscope",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "2",
                "P6_ATTEMPT_ID": "p6-12345-3",
            },
            process_environment={},
        )


def test_rootless_executor_withholds_live_provider_key_from_non_model_phase(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path)

    executor.execute_phase(
        "health",
        ("python3", "-c", "print('healthy')"),
        log_path=tmp_path / "health.log",
        provider_credentials=False,
    )

    assert "top-secret" not in fake.run_argv
    assert "Z_SCOPE_API_KEY" not in fake.run_argv
    assert all("Z_SCOPE_API_KEY" not in item for item in fake.runtime_environments)


def test_rootless_podman_uses_minimal_host_environment_and_injects_only_provider_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    injected_runtime_context = {
        "PATH": "/attacker/bin",
        "HOME": "/attacker/home",
        "XDG_RUNTIME_DIR": "/attacker/run",
        "XDG_CONFIG_HOME": "/attacker/config",
        "XDG_DATA_HOME": "/attacker/data",
        "TMPDIR": "/attacker/tmp",
        "LANG": "attacker_LOCALE",
        "LC_ALL": "attacker_LOCALE",
        "LD_LIBRARY_PATH": "/attacker/lib",
        "LD_PRELOAD": "/attacker/inject.so",
        "PYTHONPATH": "/attacker/python",
        "HTTPS_PROXY": "http://attacker.invalid:8080",
    }
    rejected = {
        "GH_PAT": "gh-secret",
        "GITHUB_PAT": "github-secret",
        "AWS_ACCESS_KEY_ID": "aws-id",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "AWS_SESSION_TOKEN": "aws-session",
        "AZURE_CLIENT_SECRET": "azure-secret",
        "GOOGLE_APPLICATION_CREDENTIALS": "/unsafe/gcp.json",
        "GCP_SERVICE_ACCOUNT_KEY": "gcp-secret",
        "JWT": "signed-jwt",
        "SSH_AUTH_SOCK": "/unsafe/agent.sock",
        "REGISTRY_AUTH_FILE": "/unsafe/auth.json",
        "Z_SCOPE_RANDOM_CANARY": "random-canary",
    }
    for key, value in {**injected_runtime_context, **rejected}.items():
        monkeypatch.setenv(key, value)

    executor, fake, _ = _executor(tmp_path, runtime="podman")
    executor.execute_phase(
        "scan",
        ("python3", "-m", "zscope.cli.cli"),
        log_path=tmp_path / "scan.log",
    )

    allowed = {"PATH", "HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "LANG", "LC_ALL"}
    for command, environment in fake.runtime_invocations:
        assert set(environment) <= allowed
        assert "Z_SCOPE_API_KEY" not in environment
        assert not any(value in environment.values() for value in injected_runtime_context.values())
        assert all(key not in environment for key in rejected)
        assert not any(value in environment.values() for value in rejected.values())

    lifecycle = {command[1] for command, _ in fake.runtime_invocations}
    assert {"info", "image", "network", "inspect", "ps", "rm"}.issubset(lifecycle)
    assert set(executor.environment) <= allowed
    assert executor.environment["PATH"] != "/attacker/bin"
    assert "LD_LIBRARY_PATH" not in executor.environment
    assert "LD_PRELOAD" not in executor.environment
    assert "PYTHONPATH" not in executor.environment
    assert "HTTPS_PROXY" not in executor.environment


def test_rootless_podman_removes_inherited_credential_shaped_image_environment(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(
        tmp_path,
        image_environment=["PATH=/usr/local/bin", "GPG_KEY=public-build-metadata"],
    )

    preflight = executor.preflight()
    executor.execute_phase(
        "scan",
        ("python3", "-m", "zscope.cli.cli"),
        log_path=tmp_path / "scan.log",
    )

    assert preflight["image_environment_unset_keys"] == ["GPG_KEY"]
    unset_index = fake.run_argv.index("--unsetenv")
    assert fake.run_argv[unset_index : unset_index + 2] == ["--unsetenv", "GPG_KEY"]
    assert "public-build-metadata" not in json.dumps(fake.run_argv)


def test_non_podman_runtime_rejects_before_image_environment_handoff(
    tmp_path: Path,
) -> None:
    executor, _, _ = _executor(
        tmp_path,
        runtime="docker",
        image_environment=["GPG_KEY=public-build-metadata"],
    )

    with pytest.raises(BenchmarkIsolationError, match="descriptor preservation"):
        executor.preflight()


def test_rootless_executor_persists_only_a_safe_phase_log(tmp_path: Path) -> None:
    executor, _, _ = _executor(
        tmp_path,
        run_stdout="candidate leaked top-secret to stdout",
        run_stderr="provider response bearer-secret",
    )
    log_path = tmp_path / "scan.log"

    executor.execute_phase("scan", ("zscope",), log_path=log_path)

    payload = json.loads(log_path.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": "zscope.oci-phase-log.v1",
        "phase": "scan",
        "outcome": "completed",
        "return_code": 0,
        "return_code_accepted": True,
        "stdout_persisted": False,
        "stderr_persisted": False,
    }
    assert "top-secret" not in log_path.read_text(encoding="utf-8")
    assert "bearer-secret" not in log_path.read_text(encoding="utf-8")


def test_rootless_executor_rejects_a_symbolic_link_phase_log(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path)
    protected = tmp_path / "protected.txt"
    protected.write_text("do-not-overwrite\n", encoding="utf-8")
    log_path = tmp_path / "scan.log"
    try:
        log_path.symlink_to(protected)
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")

    with pytest.raises(BenchmarkIsolationError, match="phase log target is unsafe"):
        executor.execute_phase("scan", ("zscope",), log_path=log_path)

    assert protected.read_text(encoding="utf-8") == "do-not-overwrite\n"
    assert not fake.run_argv
    assert executor._provider_environment == {}


def test_phase_log_rejects_parent_directory_replacement_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix":
        pytest.skip("stable directory descriptors are POSIX-only")
    parent = tmp_path / "logs"
    displaced = tmp_path / "logs-displaced"
    original_open = benchmark_isolation.os.open
    raced = False

    def racing_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal raced
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if (
            not raced
            and dir_fd is None
            and Path(path) == parent
            and flags & getattr(os, "O_DIRECTORY", 0)
        ):
            raced = True
            parent.rename(displaced)
            parent.mkdir()
        return descriptor

    monkeypatch.setattr(benchmark_isolation.os, "open", racing_open)

    with pytest.raises(BenchmarkIsolationError, match="directory identity changed"):
        benchmark_isolation._write_oci_phase_log(
            parent / "scan.log",
            {
                "schema_version": "zscope.oci-phase-log.v1",
                "phase": "scan",
            },
        )

    assert raced is True
    assert not (parent / "scan.log").exists()


def test_rootless_executor_cleans_up_when_runtime_launch_raises(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path, raise_on_run=True)

    with pytest.raises(BenchmarkIsolationError, match="runtime invocation failed") as raised:
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert "top-secret" not in str(raised.value)
    assert len(fake.removed_names) == 1
    assert fake.scanner_name == ""
    assert executor._provider_environment == {}
    assert json.loads((tmp_path / "scan.log").read_text(encoding="utf-8"))["outcome"] == (
        "launching"
    )


def test_rootless_executor_clears_key_when_non_model_phase_launch_raises(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path, raise_on_run=True)

    with pytest.raises(BenchmarkIsolationError, match="runtime invocation failed"):
        executor.execute_phase(
            "health",
            ("zscope", "--health"),
            log_path=tmp_path / "health.log",
            provider_credentials=False,
        )

    assert len(fake.removed_names) == 1
    assert executor._provider_environment == {}


def test_rootless_executor_clears_key_when_non_model_phase_evidence_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor, fake, _ = _executor(tmp_path)

    def fail_evidence(**_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("evidence failure containing top-secret")

    monkeypatch.setattr(executor, "_phase_evidence", fail_evidence)
    with pytest.raises(BenchmarkIsolationError, match="runtime invocation failed") as raised:
        executor.execute_phase(
            "index",
            ("zscope", "--index"),
            log_path=tmp_path / "index.log",
            provider_credentials=False,
        )

    assert "top-secret" not in str(raised.value)
    assert len(fake.removed_names) == 1
    assert executor._provider_environment == {}


def test_rootless_executor_clears_key_when_preflight_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor, _, _ = _executor(tmp_path)
    executor._preflight = None

    def fail_preflight() -> dict[str, Any]:
        raise BenchmarkIsolationError("fixed preflight failure")

    monkeypatch.setattr(executor, "_preflight_retaining_credentials", fail_preflight)
    with pytest.raises(BenchmarkIsolationError, match="fixed preflight failure"):
        executor.preflight()

    assert executor._provider_environment == {}


def test_rootless_executor_clears_key_on_prelaunch_validation_failure(
    tmp_path: Path,
) -> None:
    executor, _, _ = _executor(tmp_path)

    with pytest.raises(BenchmarkIsolationError, match="must be non-empty"):
        executor.execute_phase("", ("zscope",), log_path=tmp_path / "invalid.log")

    assert executor._provider_environment == {}


@pytest.mark.parametrize("interrupt_on_run", ["keyboard", "sigterm"])
def test_rootless_executor_cleans_up_and_restores_handlers_on_interrupt(
    tmp_path: Path,
    interrupt_on_run: str,
) -> None:
    executor, fake, _ = _executor(tmp_path, interrupt_on_run=interrupt_on_run)
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)

    with pytest.raises(KeyboardInterrupt):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert len(fake.removed_names) == 1
    assert fake.scanner_name == ""
    assert executor._provider_environment == {}
    assert signal.getsignal(signal.SIGTERM) == previous_term
    assert signal.getsignal(signal.SIGINT) == previous_int
    assert "top-secret" not in (tmp_path / "scan.log").read_text(encoding="utf-8")


def test_rootless_executor_mounts_complete_candidate_runtime_read_only(
    tmp_path: Path,
) -> None:
    executor, fake, _ = _executor(tmp_path, with_runtime_source=True)

    executor.execute_phase(
        "scan",
        (
            "python3",
            "-c",
            "import sys;sys.path.insert(0,'/zscope-runtime');import zscope",
        ),
        log_path=tmp_path / "scan.log",
    )
    evidence = executor.execution_evidence(required_phases=("scan",))

    assert evidence["runtime_source_mounted"] is True
    assert len(evidence["runtime_source_sha256"]) == 64
    runtime_mount = next(row for row in evidence["mounts"] if row["purpose"] == "runtime_source")
    assert runtime_mount["destination"] == "/zscope-runtime/zscope"
    assert runtime_mount["read_only"] is True
    assert any("dst=/zscope-runtime/zscope,readonly" in item for item in fake.run_argv)
    require_release_isolation(required=True, capability=evidence)


def test_rootless_executor_rejects_runtime_source_mutation_after_binding(
    tmp_path: Path,
) -> None:
    executor, _, _ = _executor(tmp_path, with_runtime_source=True)
    assert executor.runtime_source is not None
    (executor.runtime_source / "runtime_defaults.yaml").write_text(
        "version: changed\n", encoding="utf-8"
    )

    with pytest.raises(BenchmarkIsolationError, match="changed after binding"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")


def test_sealed_runtime_hash_rejects_lstat_open_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_source = tmp_path / "runtime-source"
    runtime_source.mkdir()
    (runtime_source / "__init__.py").write_text("\n", encoding="utf-8")
    victim = runtime_source / "module.py"
    victim.write_text("ORIGINAL = True\n", encoding="utf-8")
    replacement = tmp_path / "replacement.py"
    replacement.write_text("REPLACED = True\n", encoding="utf-8")
    original_open = benchmark_isolation.os.open
    replaced = False

    def racing_open(path: os.PathLike[str] | str, flags: int, *args: Any) -> int:
        nonlocal replaced
        if Path(path) == victim and not replaced:
            replaced = True
            os.replace(replacement, victim)
        return original_open(path, flags, *args)

    monkeypatch.setattr(benchmark_isolation.os, "open", racing_open)

    with pytest.raises(BenchmarkIsolationError, match="identity changed"):
        sealed_runtime_source_sha256(runtime_source)

    assert replaced is True


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"rootless": False}, "not verified rootless"),
        ({"digest_matches": False}, "pinned digest"),
        ({"internal_network": False}, "must be internal"),
        (
            {"proxy_exposes_secret_environment": True},
            "exposes credential metadata",
        ),
    ],
)
def test_rootless_executor_preflight_fails_closed(
    tmp_path: Path, options: dict[str, Any], message: str
) -> None:
    executor, _, _ = _executor(tmp_path, **options)
    with pytest.raises(BenchmarkIsolationError, match=message):
        executor.preflight()


def test_rootless_executor_rejects_inspected_mount_drift(tmp_path: Path) -> None:
    executor, _, _ = _executor(tmp_path, tamper_mounts=True)
    with pytest.raises(BenchmarkIsolationError, match="execution evidence"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")


def test_rootless_executor_rechecks_proxy_attestation_for_each_phase(tmp_path: Path) -> None:
    executor, fake, _ = _executor(tmp_path, drift_proxy_attestation_after_run=True)

    with pytest.raises(BenchmarkIsolationError, match="attested labels"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert len(fake.removed_names) == 1


def test_rootless_podman_v4_accepts_expanded_cap_drop_and_bound_network(
    tmp_path: Path,
) -> None:
    executor, _, _ = _executor(tmp_path, runtime="podman", podman_v4_inspect=True)

    result = executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")

    assert result.evidence["inspect_verified"] is True
    assert result.evidence["cap_drop_verified"] is True
    assert result.evidence["runtime_network_mode"] == "bridge"
    assert result.evidence["network_name"] == "zscope-model-only"
    assert result.evidence["network_attachment_verified"] is True


def test_rootless_podman_v4_rejects_partial_expanded_cap_drop(tmp_path: Path) -> None:
    executor, _, _ = _executor(
        tmp_path,
        runtime="podman",
        podman_v4_inspect=True,
        partial_cap_drop=True,
    )

    with pytest.raises(BenchmarkIsolationError, match="execution evidence"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")


def test_rootless_podman_v4_rejects_an_extra_network_attachment(tmp_path: Path) -> None:
    executor, _, _ = _executor(
        tmp_path,
        runtime="podman",
        podman_v4_inspect=True,
        extra_network_attachment=True,
    )

    with pytest.raises(BenchmarkIsolationError, match="execution evidence"):
        executor.execute_phase("scan", ("zscope",), log_path=tmp_path / "scan.log")


def test_rootless_podman_rejects_an_extra_filtered_network_peer(tmp_path: Path) -> None:
    executor, _, _ = _executor(tmp_path, runtime="podman", extra_network_peer=True)
    with pytest.raises(BenchmarkIsolationError, match="exactly the declared proxy"):
        executor.preflight()


def test_capability_requires_supported_runtime_and_pinned_image() -> None:
    unknown = oci_capability(
        runtime="nerdctl", image="repo@sha256:" + "a" * 64, which=lambda value: value
    )
    unpinned = oci_capability(runtime="podman", image="repo:latest", which=lambda value: value)

    assert unknown["available"] is False
    assert unpinned["available"] is False


def test_formal_runner_routes_every_scan_phase_through_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    phases: list[str] = []
    host_commands: list[list[str]] = []

    class FakeExecutor:
        def __init__(self, **kwargs: Any) -> None:
            self.cache = Path(kwargs["cache_output"])

        def preflight(self) -> dict[str, Any]:
            return {"rootless_verified": True}

        def execute_phase(
            self,
            phase: str,
            command: tuple[str, ...] | list[str],
            *,
            log_path: Path,
            accepted_returncodes: tuple[int, ...] = (0,),
            provider_credentials: bool = True,
        ) -> SimpleNamespace:
            del command, accepted_returncodes, provider_credentials
            phases.append(phase)
            log_path.write_text("ok\n", encoding="utf-8")
            if phase == "scan":
                benchmark_runner._json_dump(
                    self.cache / "project" / "report.json",
                    {
                        "run_manifest": {"source_revision": "fixture-v1"},
                        "summary": {},
                    },
                )
            return SimpleNamespace(seconds=0.1)

        def execution_evidence(self, *, required_phases: list[str]) -> dict[str, Any]:
            assert set(required_phases) == set(phases)
            return {"release_capable": True, "execution_verified": True}

    def copy_input(_source: Path, destination: Path, _language: str) -> dict[str, Any]:
        destination.mkdir()
        (destination / "demo.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        return benchmark_runner.scan_input_manifest(destination)

    def write_config(_spec: Any, project: Path, path: Path, *, scan_depth: str) -> dict[str, Any]:
        assert scan_depth == "fast"
        raw = {"config_version": 2, "project": {"root": str(project), "source_root": "."}}
        path.write_text(benchmark_runner.yaml.safe_dump(raw), encoding="utf-8")
        return raw

    def host_command(
        argv: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        log_path: Path,
        accepted_returncodes: tuple[int, ...] = (0,),
    ) -> float:
        del cwd, environment, accepted_returncodes
        host_commands.append(list(argv))
        assert "_score" in argv
        score_path = Path(argv[argv.index("--output") + 1])
        benchmark_runner._json_dump(
            score_path,
            {"queue_empty": True, "performance_telemetry": {}, "tokens": 0},
        )
        log_path.write_text("scored\n", encoding="utf-8")
        return 0.1

    effective = SimpleNamespace(
        concurrency=SimpleNamespace(validator_workers=1, llm_max_inflight=1),
        scan=SimpleNamespace(llm_profiles=SimpleNamespace(validation="default")),
        llms={
            "default": SimpleNamespace(
                base_urls=["https://models.internal/v1"],
                models=["glm-5.1"],
                base_url_max_concurrent_requests=1,
            )
        },
        llm=SimpleNamespace(
            base_urls=["https://models.internal/v1"],
            models=["glm-5.1"],
            base_url_max_concurrent_requests=1,
        ),
        runtime_provenance=SimpleNamespace(sha256="1" * 64),
        rule_catalog_provenance=SimpleNamespace(catalog_sha256="2" * 64, effective_sha256="3" * 64),
    )
    monkeypatch.setattr(benchmark_runner, "_OCI_EXECUTOR_FACTORY", FakeExecutor)
    monkeypatch.setattr(benchmark_runner, "copy_scan_input", copy_input)
    monkeypatch.setattr(benchmark_runner, "_write_execution_config", write_config)
    monkeypatch.setattr(benchmark_runner, "_validate_config", lambda *_args, **_kwargs: effective)
    monkeypatch.setattr(benchmark_runner, "_run_command", host_command)
    monkeypatch.setattr(
        benchmark_runner,
        "_tool_health",
        lambda _spec: (_ for _ in ()).throw(AssertionError("host health must not run")),
    )
    monkeypatch.setattr(
        benchmark_runner,
        "_build_fixture",
        lambda *_args: (_ for _ in ()).throw(AssertionError("host build must not run")),
    )
    monkeypatch.setattr(benchmark_runner, "require_release_isolation", lambda **_kwargs: None)
    monkeypatch.setattr(benchmark_runner, "_archive_usage_events", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(benchmark_runner, "_gate_c", lambda _score, **_kwargs: [])
    monkeypatch.setattr(benchmark_runner, "_gate_c_sealed", lambda _score: [])

    def replay(path: Path, _report: dict[str, Any]) -> dict[str, Any]:
        path.write_text("{}\n", encoding="utf-8")
        return {
            "schema_version": "zscope.validator-replay-bundle.v1",
            "group_count": 0,
            "bundle_sha256": "4" * 64,
        }

    monkeypatch.setattr(benchmark_runner, "write_validator_replay_bundle", replay)
    for key, value in {
        "Z_SCOPE_BENCHMARK_OCI_RUNTIME": "podman",
        "Z_SCOPE_BENCHMARK_OCI_IMAGE": "repo@sha256:" + "a" * 64,
        "Z_SCOPE_BENCHMARK_OCI_NETWORK": "model-only",
        "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": "proxy",
        "Z_SCOPE_LLM_BASE_URL": "https://models.internal/v1",
        "Z_SCOPE_LLM_MODEL": "glm-5.1",
        "Z_SCOPE_API_KEY": "secret",
    }.items():
        monkeypatch.setenv(key, value)

    run_dir = tmp_path / "run"
    workspace = tmp_path / "workspace"
    run_dir.mkdir()
    workspace.mkdir()
    spec = benchmark_runner.BenchmarkSpec("c_cpp", "unused-fixture", ())

    summary = benchmark_runner._run_trial_in_workspace(
        spec, run_dir, 1, mode="formal", workspace=workspace
    )

    assert phases == ["build-configure", "build", "health", "index", "scan"]
    assert len(host_commands) == 1
    assert "_score" in host_commands[0]
    assert summary["isolation"]["execution_verified"] is True
