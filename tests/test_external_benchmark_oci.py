from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import external_benchmark
from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    OciNetworkPolicy,
    RootlessOciExecutor,
)


class ExternalFakeOciRuntime:
    def __init__(
        self,
        *,
        image: str,
        scan_input: Path,
        output: Path,
        cache: Path,
        environment: dict[str, str],
        rootless: bool = True,
    ) -> None:
        self.image = image
        self.scan_input = scan_input.resolve()
        self.output = output.resolve()
        self.cache = cache.resolve()
        self.policy = OciNetworkPolicy.from_environment(environment)
        self.rootless = rootless
        self.scanner_name = ""
        self.run_argv: list[str] = []
        self.runtime_environment: dict[str, str] = {}
        self.config_text = ""
        self.entries_text = ""
        self.compile_commands_text = ""
        self.scanner_finished = False

    @staticmethod
    def _result(argv: list[str], value: Any = None, returncode: int = 0):
        stdout = "" if value is None else json.dumps(value)
        return subprocess.CompletedProcess(argv, returncode, stdout, "")

    def __call__(self, argv: list[str], **kwargs: Any):
        command = [str(value) for value in argv]
        if command[1:3] == ["info", "--format"]:
            return self._result(command, {"host": {"security": {"rootless": self.rootless}}})
        if command[1:3] == ["image", "inspect"]:
            digest = self.image.rsplit("@", 1)[1]
            return self._result(command, [{"Id": digest, "RepoDigests": ["repo@" + digest]}])
        if command[1:3] == ["network", "inspect"]:
            peers: dict[str, Any] = {"proxy123": {"Name": "model-proxy"}}
            if self.scanner_name:
                peers["scanner123"] = {"Name": self.scanner_name}
            return self._result(
                command,
                [
                    {
                        "Name": self.policy.network_name,
                        "Internal": True,
                        "Labels": {
                            "io.zscope.network-policy": "model-endpoint-only",
                            "io.zscope.network-policy-sha256": self.policy.policy_sha256,
                        },
                        "Containers": peers,
                    }
                ],
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
            self.runtime_environment = dict(kwargs.get("env") or {})
            self.config_text = (self.scan_input / "zscope.execution.yaml").read_text(
                encoding="utf-8"
            )
            self.entries_text = (self.scan_input / "entries.json").read_text(encoding="utf-8")
            compile_commands = self.scan_input / "project" / "compile_commands.json"
            if compile_commands.is_file():
                self.compile_commands_text = compile_commands.read_text(encoding="utf-8")
            report = {
                "type": "parallel_analysis_report",
                "summary": {
                    "functions_analyzed": 1,
                    "total_issues": 0,
                    "interrupted": False,
                },
                "issues": [],
                "metadata": {"interrupted": False},
                "run_manifest": {
                    "source_tree_hash": "a" * 64,
                    "config_hash": "b" * 64,
                    "effective_rules_sha256": "c" * 64,
                    "candidate_schema_version": "zscope.candidate.v3.3",
                    "knowledge_db_version": "14",
                },
            }
            (self.cache / "project" / "zscope_batch_report.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            self.scanner_finished = True
            return self._result(command)
        if command[1] == "inspect" and command[2] == self.scanner_name:
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
                                "Source": str(self.scan_input),
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


def _suite(tmp_path: Path) -> Path:
    suite = tmp_path / "suite"
    project = suite / "project"
    benchmark = suite / "benchmark"
    source = project / "src" / "demo.c"
    source.parent.mkdir(parents=True)
    benchmark.mkdir(parents=True)
    source.write_text("int entry(void) { return 0; }\n", encoding="utf-8")
    (project / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": project.as_posix(),
                    "command": f"clang -c {source.as_posix()}",
                    "file": source.as_posix(),
                }
            ]
        ),
        encoding="utf-8",
    )
    (benchmark / "entries.json").write_text(
        json.dumps({"functions": [{"function_name": "entry", "file_path": "src/demo.c"}]}),
        encoding="utf-8",
    )
    (benchmark / "ground_truth.json").write_text(
        json.dumps(
            {
                "benchmark": "external-oci-unit",
                "suite": "unit",
                "vulnerabilities": [],
                "safe_entries": [],
            }
        ),
        encoding="utf-8",
    )
    (benchmark / "manifest.json").write_text(
        json.dumps({"suite": "unit", "entries": 1, "ground_truth": 0}),
        encoding="utf-8",
    )
    (suite / "zscope.benchmark.yaml").write_text(
        "config_version: 2\n"
        "llms:\n"
        "  default:\n"
        '    base_urls: ["https://host.invalid/v1"]\n'
        '    models: ["host-model"]\n'
        "    api_key: host-key\n"
        "project:\n"
        f'  root: "{project.as_posix()}"\n'
        "  source_root: .\n"
        "  language: c_cpp\n"
        '  entry_functions_list: "../benchmark/entries.json"\n'
        "  compile_commands_path: compile_commands.json\n"
        "scan:\n"
        '  task: ""\n'
        "indexing:\n"
        "  backend: regex\n"
        "concurrency:\n"
        "  entry_workers: 1\n"
        "  validator_workers: 1\n"
        "  investigator_workers: 1\n"
        "  evidence_completion_workers: 1\n"
        "  index_workers: 1\n"
        "  svf_workers: 1\n"
        "  llm_max_inflight: 1\n",
        encoding="utf-8",
    )
    return suite


def _formal_args(suite: Path, run_dir: Path, env_file: Path) -> argparse.Namespace:
    return argparse.Namespace(
        suite_root=suite,
        run_dir=run_dir,
        mode="zscope",
        condition=external_benchmark.CONDITION_FULL_ZSCOPE,
        run_kind="formal",
        trial_index=1,
        line_tolerance=8,
        view="default",
        env_file=env_file.as_posix(),
        warm_cache=False,
    )


def _install_fake_runtime(
    monkeypatch: pytest.MonkeyPatch,
    observed: list[ExternalFakeOciRuntime],
    *,
    rootless: bool = True,
) -> None:
    def factory(**kwargs: Any) -> RootlessOciExecutor:
        fake = ExternalFakeOciRuntime(
            image=str(kwargs["image"]),
            scan_input=Path(kwargs["scan_input"]),
            output=Path(kwargs["artifact_output"]),
            cache=Path(kwargs["cache_output"]),
            environment=dict(kwargs["environment"]),
            rootless=rootless,
        )
        observed.append(fake)
        return RootlessOciExecutor(
            **kwargs,
            process_runner=fake,
            which=lambda _value: "/usr/bin/podman",
        )

    monkeypatch.setattr(external_benchmark, "_OCI_EXECUTOR_FACTORY", factory)


def _set_formal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "Z_SCOPE_BENCHMARK_OCI_RUNTIME": "podman",
        "Z_SCOPE_BENCHMARK_OCI_IMAGE": "repo@sha256:" + "d" * 64,
        "Z_SCOPE_BENCHMARK_OCI_NETWORK": "model-only",
        "Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER": "model-proxy",
        "Z_SCOPE_LLM_BASE_URL": "https://models.internal/v1",
        "Z_SCOPE_LLM_MODEL": "glm-5.1",
        "Z_SCOPE_API_KEY": "secret",
        "GROUND_TRUTH_PATH": "must-not-reach-container",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_external_formal_executes_real_rootless_oci_contract_then_scores_on_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path)
    run_dir = tmp_path / "formal-run"
    env_file = tmp_path / "missing.env"
    observed: list[ExternalFakeOciRuntime] = []
    _set_formal_environment(monkeypatch)
    _install_fake_runtime(monkeypatch, observed)
    original_load_truth = external_benchmark._load_truth

    def load_truth_after_scan(root: Path) -> dict[str, Any]:
        assert observed and observed[0].scanner_finished is True
        return original_load_truth(root)

    monkeypatch.setattr(external_benchmark, "_load_truth", load_truth_after_scan)

    summary = external_benchmark.run_prepared(_formal_args(suite, run_dir, env_file))

    fake = observed[0]
    assert summary["run"]["execution"] == "rootless_oci"
    assert summary["isolation"]["execution_verified"] is True
    assert summary["isolation"]["scoring_execution"] == "host_after_scanner_exit"
    assert summary["isolation"]["required_phases"] == ["scan"]
    assert (run_dir / "zscope_batch_report.json").is_file()
    scan_manifest = json.loads(
        (run_dir / "formal-scan-input-manifest.json").read_text(encoding="utf-8")
    )
    assert scan_manifest["answer_material_present"] is False
    assert scan_manifest["manifest_sha256"] == summary["isolation"]["scan_input_manifest_sha256"]
    assert all("ground_truth" not in row["path"].lower() for row in scan_manifest["files"])
    assert (run_dir / "isolation.json").is_file()
    assert not (suite / "project" / "zscope_batch_report.json").exists()
    assert "/zscope-cache/project" in fake.config_text
    assert "/zscope-input/entries.json" in fake.config_text
    assert "${Z_SCOPE_LLM_BASE_URL}" in fake.config_text
    assert suite.as_posix() not in fake.config_text
    assert "benchmark" not in fake.config_text.lower()
    assert "ground_truth" not in fake.config_text.lower()
    assert "answer-key" not in fake.config_text.lower()
    assert suite.as_posix() not in fake.compile_commands_text
    assert "ground_truth" not in fake.entries_text.lower()
    assert "GROUND_TRUTH_PATH" not in fake.runtime_environment
    mount_sources = {
        Path(row["source"]) for row in summary["isolation"]["mounts"] if isinstance(row, dict)
    }
    assert all(source != suite and suite not in source.parents for source in mount_sources)
    assert all(
        source != external_benchmark.REPO_ROOT
        and external_benchmark.REPO_ROOT not in source.parents
        for source in mount_sources
    )
    assert (
        next(row for row in summary["isolation"]["mounts"] if row["purpose"] == "scan_input")[
            "read_only"
        ]
        is True
    )


def test_external_formal_fails_closed_when_runtime_is_not_rootless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = _suite(tmp_path)
    observed: list[ExternalFakeOciRuntime] = []
    _set_formal_environment(monkeypatch)
    _install_fake_runtime(monkeypatch, observed, rootless=False)
    monkeypatch.setattr(
        external_benchmark,
        "_load_truth",
        lambda _root: (_ for _ in ()).throw(AssertionError("scorer must not run")),
    )

    with pytest.raises(BenchmarkIsolationError, match="not verified rootless"):
        external_benchmark.run_prepared(
            _formal_args(suite, tmp_path / "formal-failed", tmp_path / "missing.env")
        )

    assert observed and observed[0].scanner_finished is False
    assert not (suite / "project" / "zscope_batch_report.json").exists()


@pytest.mark.parametrize(
    "condition",
    [
        external_benchmark.CONDITION_CANDIDATES,
        external_benchmark.CONDITION_PURE_LLM_ENTRY,
        external_benchmark.CONDITION_PURE_LLM_REPO,
    ],
)
def test_external_formal_rejects_non_full_conditions_before_execution(
    tmp_path: Path, condition: str
) -> None:
    suite = _suite(tmp_path)
    args = _formal_args(suite, tmp_path / "formal-rejected", tmp_path / "missing.env")
    args.condition = condition

    with pytest.raises(ValueError, match="full_zscope_pipeline only"):
        external_benchmark.run_prepared(args)
