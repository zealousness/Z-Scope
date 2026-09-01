from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.p6_oci_cleanup import P6OciCleanupError, cleanup_p6_oci_scanners
from zscope.benchmarking.isolation import (
    P6_OCI_CLEANUP_SCHEMA_VERSION,
    P6_OCI_CONCURRENCY_GROUP,
    P6_OCI_LABEL_ATTEMPT_ID,
    P6_OCI_LABEL_CONCURRENCY_GROUP,
    P6_OCI_LABEL_PHASE,
    P6_OCI_LABEL_REPOSITORY,
    P6_OCI_LABEL_SCHEMA,
    P6_OCI_LABEL_WORKFLOW_RUN_ATTEMPT,
    P6_OCI_LABEL_WORKFLOW_RUN_ID,
)


def _labels(*, run_id: str, run_attempt: str, repository: str = "example/zscope") -> dict[str, str]:
    return {
        "io.zscope.role": "scanner",
        P6_OCI_LABEL_SCHEMA: P6_OCI_CLEANUP_SCHEMA_VERSION,
        P6_OCI_LABEL_CONCURRENCY_GROUP: P6_OCI_CONCURRENCY_GROUP,
        P6_OCI_LABEL_REPOSITORY: repository,
        P6_OCI_LABEL_WORKFLOW_RUN_ID: run_id,
        P6_OCI_LABEL_WORKFLOW_RUN_ATTEMPT: run_attempt,
        P6_OCI_LABEL_ATTEMPT_ID: f"p6-{run_id}-{run_attempt}",
        P6_OCI_LABEL_PHASE: "scan",
    }


class FakeCleanupRuntime:
    def __init__(self, containers: list[dict[str, Any]]) -> None:
        self.containers = {str(item["Id"]): item for item in containers}
        self.removed: list[str] = []
        self.environments: list[dict[str, str]] = []

    @staticmethod
    def _result(argv: list[str], *, stdout: str = "", returncode: int = 0):
        return subprocess.CompletedProcess(argv, returncode, stdout, "runtime secret stderr")

    def __call__(self, argv: list[str], **kwargs: Any):
        command = [str(value) for value in argv]
        self.environments.append(dict(kwargs.get("env") or {}))
        if command[1:3] == ["ps", "--all"]:
            assert command[3] == "--no-trunc"
            filters = [
                command[index + 1].removeprefix("label=")
                for index, value in enumerate(command[:-1])
                if value == "--filter"
            ]
            matches = []
            for identity, inspect in self.containers.items():
                labels = inspect["Config"]["Labels"]
                if all(
                    "=" in item and labels.get(item.split("=", 1)[0]) == item.split("=", 1)[1]
                    for item in filters
                ):
                    matches.append(identity)
            return self._result(command, stdout="\n".join(matches) + ("\n" if matches else ""))
        if command[1] == "inspect":
            listed = command[2]
            rows = [
                item for identity, item in self.containers.items() if identity.startswith(listed)
            ]
            return self._result(command, stdout=json.dumps(rows))
        if command[1:3] == ["rm", "--force"]:
            identity = command[3]
            if identity not in self.containers:
                return self._result(command, returncode=1)
            self.removed.append(identity)
            self.containers.pop(identity)
            return self._result(command)
        raise AssertionError(f"unexpected cleanup command: {command}")


def _container(identity_character: str, labels: dict[str, str]) -> dict[str, Any]:
    identity = identity_character * 64
    phase = labels[P6_OCI_LABEL_PHASE]
    return {
        "Id": identity,
        "Name": f"/zscope-benchmark-{phase}-{identity[-12:]}",
        "Config": {
            "Labels": dict(labels),
            "Env": [],
        },
    }


def _cleanup(
    tmp_path: Path,
    runtime: FakeCleanupRuntime,
    *,
    mode: str,
    run_id: str = "12345",
    run_attempt: str = "2",
) -> int:
    runtime_path = tmp_path / "podman"
    return cleanup_p6_oci_scanners(
        runtime="podman",
        mode=mode,
        repository="example/zscope",
        workflow_run_id=run_id,
        workflow_run_attempt=run_attempt,
        attempt_id=f"p6-{run_id}-{run_attempt}",
        process_runner=runtime,
        which=lambda _: str(runtime_path),
    )


def test_current_cleanup_removes_only_exact_run_attempt_and_scrubs_child_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = _container("a", _labels(run_id="12345", run_attempt="2"))
    other = _container("b", _labels(run_id="12345", run_attempt="1"))
    runtime = FakeCleanupRuntime([current, other])
    monkeypatch.setenv("Z_SCOPE_API_KEY", "host-secret")
    monkeypatch.setenv("Z_SCOPE_P6_API_KEY_FILE", "/private/key-file")
    monkeypatch.setenv("PATH", "/attacker/bin")
    monkeypatch.setenv("HOME", "/attacker/home")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/attacker/run")
    monkeypatch.setenv("LD_PRELOAD", "/attacker/inject.so")
    monkeypatch.setenv("PYTHONPATH", "/attacker/python")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:8080")

    assert _cleanup(tmp_path, runtime, mode="current") == 1

    assert runtime.removed == [current["Id"]]
    assert other["Id"] in runtime.containers
    assert all("Z_SCOPE_API_KEY" not in item for item in runtime.environments)
    assert all("Z_SCOPE_P6_API_KEY_FILE" not in item for item in runtime.environments)
    assert all(item["PATH"] != "/attacker/bin" for item in runtime.environments)
    assert all(
        "HOME" not in item or item["HOME"] != "/attacker/home" for item in runtime.environments
    )
    assert all(
        "XDG_RUNTIME_DIR" not in item or item["XDG_RUNTIME_DIR"] != "/attacker/run"
        for item in runtime.environments
    )
    assert all("LD_PRELOAD" not in item for item in runtime.environments)
    assert all("PYTHONPATH" not in item for item in runtime.environments)
    assert all("HTTPS_PROXY" not in item for item in runtime.environments)


def test_stale_cleanup_removes_all_verified_scanners_in_serialized_repository_scope(
    tmp_path: Path,
) -> None:
    first = _container("a", _labels(run_id="12345", run_attempt="2"))
    second = _container("b", _labels(run_id="67890", run_attempt="1"))
    foreign = _container("c", _labels(run_id="12345", run_attempt="2", repository="other/project"))
    runtime = FakeCleanupRuntime([first, second, foreign])

    assert _cleanup(tmp_path, runtime, mode="stale") == 2

    assert runtime.removed == [first["Id"], second["Id"]]
    assert list(runtime.containers) == [foreign["Id"]]


@pytest.mark.parametrize("mutation", ["attempt", "name", "phase"])
def test_cleanup_refuses_unverified_or_mismatched_targets(tmp_path: Path, mutation: str) -> None:
    labels = _labels(run_id="12345", run_attempt="2")
    container = _container("a", labels)
    if mutation == "attempt":
        container["Config"]["Labels"][P6_OCI_LABEL_ATTEMPT_ID] = "p6-12345-3"
    elif mutation == "name":
        container["Name"] = "/unowned-container"
    else:
        container["Name"] = "/zscope-benchmark-build-aaaaaaaaaaaa"
    runtime = FakeCleanupRuntime([container])

    with pytest.raises(P6OciCleanupError, match="identity"):
        _cleanup(tmp_path, runtime, mode="stale")

    assert runtime.removed == []


def test_cleanup_refuses_same_prefix_cross_job_replacement(tmp_path: Path) -> None:
    container = _container("a", _labels(run_id="12345", run_attempt="2"))
    runtime = FakeCleanupRuntime([container])
    listed_id = container["Id"]
    container["Id"] = listed_id[:12] + "b" * 52

    with pytest.raises(P6OciCleanupError, match="identity"):
        _cleanup(tmp_path, runtime, mode="stale")

    assert runtime.removed == []
