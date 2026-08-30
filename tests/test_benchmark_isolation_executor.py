from __future__ import annotations

import json
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    OciNetworkPolicy,
    P6OciCleanupScope,
    RootlessOciExecutor,
    oci_capability,
    require_release_isolation,
)
from zscope.benchmarking import runner as benchmark_runner
from zscope.benchmarking.provider_runtime import ProviderRuntimeContract


class FakeOciRuntime:
    def __init__(
        self,
        *,
        runtime: str,
        image: str,
        scan_input: Path,
        output: Path,
        cache: Path,
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
        drift_proxy_attestation_after_run: bool = False,
        drift_cleanup_scope_after_run: bool = False,
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
        self.drift_proxy_attestation_after_run = drift_proxy_attestation_after_run
        self.drift_cleanup_scope_after_run = drift_cleanup_scope_after_run
        self.run_stdout = run_stdout
        self.run_stderr = run_stderr
        self.raise_on_run = raise_on_run
        self.interrupt_on_run = interrupt_on_run
        self.scanner_name = ""
        self.run_argv: list[str] = []
        self.scanner_environment: list[str] = []
        self.scanner_labels: dict[str, str] = {}
        self.runtime_environments: list[dict[str, str]] = []
        self.removed_names: list[str] = []

    @staticmethod
    def _result(argv: list[str], value: Any = None, returncode: int = 0, *, stderr: str = ""):
        stdout = "" if value is None else json.dumps(value)
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    def __call__(self, argv: list[str], **kwargs: Any):
        command = [str(value) for value in argv]
        self.runtime_environments.append(dict(kwargs.get("env") or {}))
        if command[1:3] == ["info", "--format"]:
            if self.runtime == "podman":
                return self._result(command, {"host": {"security": {"rootless": self.rootless}}})
            options = ["name=rootless"] if self.rootless else ["name=seccomp"]
            return self._result(command, {"SecurityOptions": options})
        if command[1:3] == ["image", "inspect"]:
            digest = self.image.rsplit("@", 1)[1] if self.digest_matches else "sha256:" + "b" * 64
            return self._result(command, [{"Id": digest, "RepoDigests": ["repo@" + digest]}])
        if self.runtime == "podman" and command[1:3] == ["ps", "--all"]:
            assert command[3:5] == ["--filter", f"network={self.policy.network_name}"]
            rows: list[dict[str, Any]] = [
                {"Id": "proxy123", "Networks": [self.policy.network_name]}
            ]
            if self.scanner_name:
                rows.append({"Id": "scanner123", "Networks": [self.policy.network_name]})
            if self.extra_network_peer:
                rows.append({"Id": "unexpected123", "Networks": [self.policy.network_name]})
            return self._result(command, rows)
        if command[1:3] == ["network", "inspect"]:
            peers: dict[str, Any] = {"proxy123": {"Name": "model-proxy"}}
            if self.scanner_name:
                peers["scanner123"] = {"Name": self.scanner_name}
            if self.extra_network_peer:
                peers["unexpected123"] = {"Name": "unexpected"}
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
            return self._result(
                command,
                [
                    {
                        "Id": "proxy123",
                        "Config": {
                            "Labels": {
                                "io.zscope.role": (
                                    "unexpected-proxy" if drifted else "model-endpoint-proxy"
                                ),
                                "io.zscope.network-policy-sha256": (
                                    "e" * 64 if drifted else self.policy.policy_sha256
                                ),
                            },
                            "Env": (
                                ["Z_SCOPE_API_KEY=proxy-secret"]
                                if self.proxy_exposes_secret_environment
                                else []
                            ),
                        },
                        "State": {"Running": True},
                        "NetworkSettings": {
                            "Networks": {
                                self.policy.network_name: {
                                    "Aliases": [self.policy.endpoint_host, "model-proxy"]
                                }
                            }
                        },
                    }
                ],
            )
        if command[1] == "run":
            self.scanner_name = command[command.index("--name") + 1]
            self.run_argv = command
            runtime_environment = dict(kwargs.get("env") or {})
            self.scanner_environment = []
            self.scanner_labels = {}
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
            if self.raise_on_run:
                raise RuntimeError("runtime failure containing top-secret")
            if self.interrupt_on_run == "keyboard":
                raise KeyboardInterrupt()
            if self.interrupt_on_run == "sigterm":
                handler = signal.getsignal(signal.SIGTERM)
                assert callable(handler)
                handler(signal.SIGTERM, None)
            return subprocess.CompletedProcess(command, 0, self.run_stdout, self.run_stderr)
        if command[1] == "inspect" and command[2] == self.scanner_name:
            input_source = self.output if self.tamper_mounts else self.scan_input
            return self._result(
                command,
                [
                    {
                        "Id": "scanner123",
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
            self.removed_names.append(command[3])
            self.scanner_name = ""
            return self._result(command)
        raise AssertionError(f"unexpected OCI command: {command}")


def _executor(
    tmp_path: Path,
    *,
    runtime: str = "podman",
    with_runtime_source: bool = False,
    p6_cleanup_scope: bool = False,
    **fake_options: Any,
) -> tuple[RootlessOciExecutor, FakeOciRuntime, Path]:
    scan_input = tmp_path / "sealed"
    output = tmp_path / "output"
    cache = tmp_path / "cache"
    for path in (scan_input, output, cache):
        path.mkdir()
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
        config_sha256="c" * 64,
        required_environment_keys=("Z_SCOPE_API_KEY",),
        identity_sha256="d" * 64,
    )
    fake = FakeOciRuntime(
        runtime=runtime,
        image=image,
        scan_input=scan_input,
        output=output,
        cache=cache,
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
    )
    return executor, fake, scan_input


@pytest.mark.parametrize("runtime", ["podman", "docker"])
def test_rootless_executor_collects_runtime_inspection_evidence(
    tmp_path: Path, runtime: str
) -> None:
    executor, fake, scan_input = _executor(tmp_path, runtime=runtime)

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
    ] == ["Z_SCOPE_API_KEY"]
    assert ["--env", "Z_SCOPE_API_KEY"] == fake.run_argv[
        fake.run_argv.index("--env") : fake.run_argv.index("--env") + 2
    ]
    assert result.evidence["scanner_provider_environment_verified"] is True
    assert result.evidence["scanner_provider_environment_keys"] == ["Z_SCOPE_API_KEY"]
    assert result.evidence["cancellation_cleanup_guard_verified"] is True
    assert result.evidence["stdout_persisted"] is False
    assert result.evidence["stderr_persisted"] is False
    assert (
        sum(item.get("Z_SCOPE_API_KEY") == "top-secret" for item in fake.runtime_environments) == 1
    )
    assert "Z_SCOPE_API_KEY" not in executor.environment
    assert executor._provider_environment == {}
    assert "top-secret" not in json.dumps(evidence)
    assert "Z_SCOPE_LLM_BASE_URL" not in fake.run_argv
    assert "Z_SCOPE_LLM_MODEL" not in fake.run_argv
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

    with pytest.raises(BenchmarkIsolationError, match="execution evidence"):
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
