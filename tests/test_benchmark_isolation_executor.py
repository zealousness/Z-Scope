from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    OciNetworkPolicy,
    RootlessOciExecutor,
    oci_capability,
    require_release_isolation,
)
from zscope.benchmarking import runner as benchmark_runner


class FakeOciRuntime:
    def __init__(
        self,
        *,
        runtime: str,
        image: str,
        scan_input: Path,
        output: Path,
        cache: Path,
        environment: dict[str, str],
        rootless: bool = True,
        digest_matches: bool = True,
        internal_network: bool = True,
        tamper_mounts: bool = False,
        extra_network_peer: bool = False,
    ) -> None:
        self.runtime = runtime
        self.image = image
        self.scan_input = scan_input.resolve()
        self.output = output.resolve()
        self.cache = cache.resolve()
        self.policy = OciNetworkPolicy.from_environment(environment)
        self.rootless = rootless
        self.digest_matches = digest_matches
        self.internal_network = internal_network
        self.tamper_mounts = tamper_mounts
        self.extra_network_peer = extra_network_peer
        self.scanner_name = ""
        self.run_argv: list[str] = []

    @staticmethod
    def _result(argv: list[str], value: Any = None, returncode: int = 0):
        stdout = "" if value is None else json.dumps(value)
        return subprocess.CompletedProcess(argv, returncode, stdout, "")

    def __call__(self, argv: list[str], **_: Any):
        command = [str(value) for value in argv]
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
            return self._result(
                command,
                [
                    {
                        "Id": "proxy123",
                        "Config": {
                            "Labels": {
                                "io.zscope.role": "model-endpoint-proxy",
                                "io.zscope.network-policy-sha256": self.policy.policy_sha256,
                            }
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
            return self._result(command)
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
                            },
                        },
                        "HostConfig": {
                            "ReadonlyRootfs": True,
                            "CapDrop": ["ALL"],
                            "SecurityOpt": ["no-new-privileges:true"],
                            "NetworkMode": self.policy.network_name,
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
                        ],
                        "NetworkSettings": {
                            "Networks": {self.policy.network_name: {"Aliases": [self.scanner_name]}}
                        },
                    }
                ],
            )
        if command[1:3] == ["rm", "--force"]:
            self.scanner_name = ""
            return self._result(command)
        raise AssertionError(f"unexpected OCI command: {command}")


def _executor(
    tmp_path: Path,
    *,
    runtime: str = "podman",
    **fake_options: Any,
) -> tuple[RootlessOciExecutor, FakeOciRuntime, Path]:
    scan_input = tmp_path / "sealed"
    output = tmp_path / "output"
    cache = tmp_path / "cache"
    for path in (scan_input, output, cache):
        path.mkdir()
    (scan_input / "demo.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    environment = {
        "Z_SCOPE_API_KEY": "top-secret",
        "Z_SCOPE_LLM_BASE_URL": "https://models.internal/v1",
        "Z_SCOPE_LLM_MODEL": "glm-5.1",
        "Z_SCOPE_BENCHMARK_OCI_NETWORK": "zscope-model-only",
        "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": "model-proxy",
    }
    image = "registry.example/zscope@sha256:" + "a" * 64
    fake = FakeOciRuntime(
        runtime=runtime,
        image=image,
        scan_input=scan_input,
        output=output,
        cache=cache,
        environment=environment,
        **fake_options,
    )
    executor = RootlessOciExecutor(
        runtime=runtime,
        image=image,
        scan_input=scan_input,
        artifact_output=output,
        cache_output=cache,
        environment=environment,
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
    assert ["--env", "Z_SCOPE_API_KEY"] == fake.run_argv[
        fake.run_argv.index("--env") : fake.run_argv.index("--env") + 2
    ]
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


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"rootless": False}, "not verified rootless"),
        ({"digest_matches": False}, "pinned digest"),
        ({"internal_network": False}, "must be internal"),
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
        ) -> SimpleNamespace:
            del command, accepted_returncodes
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
        llms={"default": SimpleNamespace(base_url_max_concurrent_requests=1)},
        llm=SimpleNamespace(base_url_max_concurrent_requests=1),
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
