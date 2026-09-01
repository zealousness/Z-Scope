from __future__ import annotations

import asyncio
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import p6_local_runtime as p6_local_runtime_cli
from scripts import p6_tcp_relay
from zscope.benchmarking.p6_local_runtime import (
    BASE_IMAGE_DIGEST,
    BASE_IMAGE_REF,
    P6LocalRuntimeError,
    ProxyProvisionRequest,
    build_bootstrap_proxy_attestation,
    build_expected_proxy_attestation,
    build_toolchain_image,
    load_image_provenance,
    load_runtime_lock,
    provision_transparent_proxy,
)
from zscope.benchmarking.p6_protocol import (
    canonical_sha256,
    load_expected_proxy_attestation,
    seal_toolchain_evidence,
)
from zscope.benchmarking.provider_runtime import ProviderRuntimeContract


REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TOOLS = (
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


def test_local_preflight_cli_requires_exact_run_identity_and_absolute_outputs(
    tmp_path: Path,
) -> None:
    arguments = [
        "preflight",
        "--image",
        "repo/image@sha256:" + "a" * 64,
        "--image-provenance",
        str(tmp_path / "image.json"),
        "--proxy-provision",
        str(tmp_path / "proxy.json"),
        "--network",
        "internal",
        "--egress-network",
        "egress",
        "--proxy-container",
        "proxy",
        "--repository",
        "local/zscope",
        "--workflow-run-id",
        "123",
        "--workflow-run-attempt",
        "1",
        "--attempt-id",
        "p6-wrong",
        "--control-plane-commit",
        "b" * 40,
        "--candidate-commit",
        "c" * 40,
        "--candidate-root",
        str(tmp_path),
        "--toolchain-evidence",
        str((tmp_path / "toolchain.json").absolute()),
        "--expected-proxy-attestation",
        str((tmp_path / "attestation.json").absolute()),
    ]
    with pytest.raises(RuntimeError, match="identity is invalid"):
        p6_local_runtime_cli.main(arguments)


def _toolchain_probe() -> dict[str, Any]:
    return {
        "schema_version": "zscope.p6-toolchain-probe.v1",
        "required_tools": list(REQUIRED_TOOLS),
        "paths": {name: f"/opt/zscope-tools/{name}" for name in REQUIRED_TOOLS},
        "versions": {
            name: f"{name} test-version" for name in ("python3", "cmake", "gcc", "clang", "clangd")
        },
        "missing_shared_libraries": {"wpa": [], "saber": []},
        "passed": True,
    }


def _rootfs_probe(*, requirements: bytes, verifier: bytes) -> dict[str, Any]:
    return {
        "schema_version": "zscope.p6-image-rootfs-probe.v1",
        "files": {
            "/opt/zscope/requirements/py313.txt": hashlib.sha256(requirements).hexdigest(),
            "/opt/zscope/verify_toolchain.py": hashlib.sha256(verifier).hexdigest(),
        },
        "python_customization_paths": [],
    }


def _result(
    argv: list[str], value: Any = None, *, code: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        argv,
        code,
        "" if value is None else json.dumps(value),
        "",
    )


def test_runtime_lock_pins_base_archives_and_full_range_toolchain(tmp_path: Path) -> None:
    lock, digest = load_runtime_lock(REPO_ROOT / "containers/p6/runtime-lock.json")

    assert lock["base_image"] == {
        "ref": BASE_IMAGE_REF,
        "digest": BASE_IMAGE_DIGEST,
        "python_version": "3.13.15",
    }
    assert {row["sha256"] for row in lock["archives"]} == {
        "b7752da03a298493357975aa54bd79b58eaafefae480747a6de1b92a466d88fb",
        "ad44622798179c7a507c0b8ed58c5bc46ecb0ebf9f8e22913b0141dce23771d9",
    }
    assert set(lock["required_tools"]) == {
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
    }
    assert len(digest) == 64

    tampered = json.loads((REPO_ROOT / "containers/p6/runtime-lock.json").read_text("utf-8"))
    tampered["base_image"]["digest"] = "sha256:" + "0" * 64
    path = tmp_path / "runtime-lock.json"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(P6LocalRuntimeError, match="base image"):
        load_runtime_lock(path)


class ImageBuildRuntime:
    def __init__(self, *, lock_sha: str, containerfile_sha: str, git_revision: str) -> None:
        self.lock_sha = lock_sha
        self.containerfile_sha = containerfile_sha
        self.git_revision = git_revision
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []
        self.build_context_path: Path | None = None
        self.build_context_transport: str | None = None
        self.build_context_files: dict[str, bytes] = {}
        self.private_context_snapshots: list[dict[str, tuple[bool, tuple[str, ...]]]] = []
        self.digest = "sha256:" + "a" * 64

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = [str(value) for value in argv]
        self.commands.append(command)
        environment = dict(kwargs.get("env") or {})
        self.environments.append(environment)
        self.private_context_snapshots.append(
            {
                key: (Path(environment[key]).is_dir(), tuple(Path(environment[key]).iterdir()))
                for key in ("TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME")
            }
        )
        if command[1] == "build":
            assert command[-1] == "-"
            assert kwargs.get("text") is False
            payload = kwargs.get("input")
            assert isinstance(payload, bytes)
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
                self.build_context_files = {
                    member.name: archive.extractfile(member).read()  # type: ignore[union-attr]
                    for member in archive.getmembers()
                }
            self.build_context_transport = "stdin-tar"
            assert "--file" not in command
            return _result(command)
        if command[1:3] == ["image", "inspect"]:
            return _result(
                command,
                [
                    {
                        "Id": self.digest,
                        "Digest": self.digest,
                        "RepoDigests": ["localhost/zscope-p6@" + self.digest],
                        "Config": {
                            "Env": ["PATH=/usr/local/bin:/usr/bin"],
                            "Entrypoint": None,
                            "Cmd": ["python3", "--version"],
                            "WorkingDir": "/zscope-input",
                            "Labels": {
                                "org.opencontainers.image.base.digest": BASE_IMAGE_DIGEST,
                                "org.opencontainers.image.revision": self.git_revision,
                                "io.zscope.p6-runtime-lock-sha256": self.lock_sha,
                                "io.zscope.p6-containerfile-sha256": self.containerfile_sha,
                            },
                        },
                    }
                ],
            )
        if command[1] == "run":
            if "-c" in command:
                return _result(
                    command,
                    _rootfs_probe(
                        requirements=self.build_context_files["requirements/release/py313.txt"],
                        verifier=self.build_context_files["containers/p6/verify_toolchain.py"],
                    ),
                )
            return _result(command, _toolchain_probe())
        raise AssertionError(command)


def test_image_build_binds_labels_digest_probe_and_scrubs_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path = REPO_ROOT / "containers/p6/runtime-lock.json"
    containerfile = REPO_ROOT / "containers/p6/Containerfile"
    _, lock_sha = load_runtime_lock(lock_path)
    containerfile_sha = hashlib.sha256(containerfile.read_bytes()).hexdigest()
    git_revision = "1" * 40
    runtime = ImageBuildRuntime(
        lock_sha=lock_sha,
        containerfile_sha=containerfile_sha,
        git_revision=git_revision,
    )
    sensitive_keys = {
        "Z_SCOPE_API_KEY",
        "GH_PAT",
        "GITHUB_PAT",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "GROUND_TRUTH_CANARY",
    }
    for key in sensitive_keys:
        monkeypatch.setenv(key, "must-not-cross-build-boundary")
    monkeypatch.setenv("ZSCOPE_SAFE_BUILD_CANARY", "must-not-cross-build-boundary")
    monkeypatch.setenv("LD_PRELOAD", "C:/attacker.dll")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid")
    monkeypatch.setenv("XDG_CONFIG_HOME", "C:/attacker-config")
    monkeypatch.setenv("PATH", "C:/attacker-bin")
    output = tmp_path / "image-provenance.json"

    result = build_toolchain_image(
        runtime="podman",
        repository="zscope-p6",
        git_revision=git_revision,
        lock_path=lock_path,
        containerfile=containerfile,
        context=REPO_ROOT,
        output=output,
        process_runner=runtime,
    )

    build = runtime.commands[0]
    assert "--pull=missing" in build
    assert f"PYTHON_BASE_IMAGE={BASE_IMAGE_REF}" in build
    probe = runtime.commands[-1]
    assert ["--network=none", "--read-only", "--cap-drop=all"] == [
        item for item in probe if item in {"--network=none", "--read-only", "--cap-drop=all"}
    ]
    assert result["base_image_digest"] == BASE_IMAGE_DIGEST
    assert result["image_ref"] == "localhost/zscope-p6@" + runtime.digest
    assert result["runtime_lock_sha256"] == lock_sha
    assert result["containerfile_sha256"] == containerfile_sha
    assert (
        result["python_requirements_sha256"]
        == hashlib.sha256((REPO_ROOT / "requirements/release/py313.txt").read_bytes()).hexdigest()
    )
    assert result["credential_material_present"] is False
    assert all(sensitive_keys.isdisjoint(environment) for environment in runtime.environments)
    assert all(
        set(environment)
        == {
            "HOME",
            "LANG",
            "PATH",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_RUNTIME_DIR",
        }
        for environment in runtime.environments
    )
    assert all(
        environment["PATH"].startswith("/usr/local/sbin:") for environment in runtime.environments
    )
    assert all("attacker" not in json.dumps(environment) for environment in runtime.environments)
    assert all(
        all(exists and rows == () for exists, rows in snapshot.values())
        for snapshot in runtime.private_context_snapshots
    )
    assert runtime.build_context_path is None
    assert runtime.build_context_transport == "stdin-tar"
    assert set(runtime.build_context_files) == {
        "Containerfile",
        "containers/p6/runtime-lock.json",
        "containers/p6/verify_toolchain.py",
        "requirements/release/py313.txt",
    }
    assert "must-not-cross-build-boundary" not in output.read_text(encoding="utf-8")


def _minimal_source_context(destination: Path) -> Path:
    for relative in (
        "containers/p6/Containerfile",
        "containers/p6/runtime-lock.json",
        "containers/p6/verify_toolchain.py",
        "requirements/release/py313.txt",
    ):
        source = REPO_ROOT.joinpath(*relative.split("/"))
        target = destination.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return destination


def test_image_build_uses_ephemeral_four_file_context_and_excludes_canaries(
    tmp_path: Path,
) -> None:
    source_context = _minimal_source_context(tmp_path / "source")
    canaries = {
        "test/range/zscope.local.env": b"Z_SCOPE_API_KEY=build-context-secret\n",
        ".git/config": b"build-context-git-canary\n",
        "test/range/benchmark/ground_truth.json": b"build-context-truth-canary\n",
        "GROUND_TRUTH.md": b"build-context-answer-canary\n",
    }
    for relative, content in canaries.items():
        path = source_context.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    lock_path = source_context / "containers/p6/runtime-lock.json"
    containerfile = source_context / "containers/p6/Containerfile"
    _, lock_sha = load_runtime_lock(lock_path)
    containerfile_sha = hashlib.sha256(containerfile.read_bytes()).hexdigest()
    runtime = ImageBuildRuntime(
        lock_sha=lock_sha,
        containerfile_sha=containerfile_sha,
        git_revision="2" * 40,
    )

    build_toolchain_image(
        runtime="podman",
        repository="zscope-p6",
        git_revision="2" * 40,
        lock_path=lock_path,
        containerfile=containerfile,
        context=source_context,
        output=tmp_path / "image-provenance.json",
        process_runner=runtime,
    )

    assert runtime.build_context_path is None
    assert runtime.build_context_transport == "stdin-tar"
    captured = b"\n".join(runtime.build_context_files.values())
    assert set(runtime.build_context_files) == {
        "Containerfile",
        "containers/p6/runtime-lock.json",
        "containers/p6/verify_toolchain.py",
        "requirements/release/py313.txt",
    }
    assert all(content not in captured for content in canaries.values())


def test_image_build_rejects_caller_source_outside_exact_context_layout(
    tmp_path: Path,
) -> None:
    source_context = _minimal_source_context(tmp_path / "source")
    outside_lock = tmp_path / "runtime-lock.json"
    shutil.copy2(source_context / "containers/p6/runtime-lock.json", outside_lock)
    runtime = ImageBuildRuntime(
        lock_sha="0" * 64,
        containerfile_sha="0" * 64,
        git_revision="3" * 40,
    )

    with pytest.raises(P6LocalRuntimeError, match="exact build-context path"):
        build_toolchain_image(
            runtime="podman",
            repository="zscope-p6",
            git_revision="3" * 40,
            lock_path=outside_lock,
            containerfile=source_context / "containers/p6/Containerfile",
            context=source_context,
            output=tmp_path / "image-provenance.json",
            process_runner=runtime,
        )
    assert runtime.commands == []


def test_image_build_failure_uses_closed_stdin_archive_without_context_path(
    tmp_path: Path,
) -> None:
    source_context = _minimal_source_context(tmp_path / "source")
    captured_archive: bytes | None = None

    def fail_build(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal captured_archive
        assert argv[-1] == "-"
        captured_archive = kwargs.get("input")
        assert isinstance(captured_archive, bytes)
        return _result(argv, code=1)

    with pytest.raises(P6LocalRuntimeError, match="image build failed"):
        build_toolchain_image(
            runtime="podman",
            repository="zscope-p6",
            git_revision="4" * 40,
            lock_path=source_context / "containers/p6/runtime-lock.json",
            containerfile=source_context / "containers/p6/Containerfile",
            context=source_context,
            output=tmp_path / "image-provenance.json",
            process_runner=fail_build,
        )
    assert captured_archive is not None
    assert b"Z_SCOPE_API_KEY" not in captured_archive


def test_image_build_archive_is_immune_to_source_swap_during_build(tmp_path: Path) -> None:
    source_context = _minimal_source_context(tmp_path / "source")
    lock_path = source_context / "containers/p6/runtime-lock.json"
    containerfile = source_context / "containers/p6/Containerfile"
    _, lock_sha = load_runtime_lock(lock_path)
    runtime = ImageBuildRuntime(
        lock_sha=lock_sha,
        containerfile_sha=hashlib.sha256(containerfile.read_bytes()).hexdigest(),
        git_revision="5" * 40,
    )

    def mutate_source(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if argv[1] == "build":
            source = source_context / "containers/p6/verify_toolchain.py"
            original = source.read_bytes()
            source.write_bytes(b"attacker source replacement\n")
            try:
                result = runtime(argv, **kwargs)
            finally:
                source.write_bytes(original)
            assert runtime.build_context_files["containers/p6/verify_toolchain.py"] == original
            return result
        return runtime(argv, **kwargs)

    build_toolchain_image(
        runtime="podman",
        repository="zscope-p6",
        git_revision="5" * 40,
        lock_path=lock_path,
        containerfile=containerfile,
        context=source_context,
        output=tmp_path / "image-provenance.json",
        process_runner=mutate_source,
    )

    assert runtime.build_context_transport == "stdin-tar"


@pytest.mark.parametrize("case", ("requirements", "verifier", "sitecustomize"))
def test_image_build_fails_closed_on_rootfs_identity_drift(tmp_path: Path, case: str) -> None:
    source_context = _minimal_source_context(tmp_path / "source")
    lock_path = source_context / "containers/p6/runtime-lock.json"
    containerfile = source_context / "containers/p6/Containerfile"
    _, lock_sha = load_runtime_lock(lock_path)
    base = ImageBuildRuntime(
        lock_sha=lock_sha,
        containerfile_sha=hashlib.sha256(containerfile.read_bytes()).hexdigest(),
        git_revision="b" * 40,
    )

    def corrupt_rootfs(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = base(argv, **kwargs)
        if argv[1] != "run" or "-c" not in argv:
            return result
        value = json.loads(result.stdout)
        if case == "requirements":
            value["files"]["/opt/zscope/requirements/py313.txt"] = "0" * 64
        elif case == "verifier":
            value["files"]["/opt/zscope/verify_toolchain.py"] = "0" * 64
        elif case == "sitecustomize":
            value["python_customization_paths"] = [
                "/usr/local/lib/python3.13/site-packages/sitecustomize.py"
            ]
        else:
            raise AssertionError(case)
        return _result(argv, value)

    with pytest.raises(P6LocalRuntimeError, match="rootfs"):
        build_toolchain_image(
            runtime="podman",
            repository="zscope-p6",
            git_revision="b" * 40,
            lock_path=lock_path,
            containerfile=containerfile,
            context=source_context,
            output=tmp_path / "image-provenance.json",
            process_runner=corrupt_rootfs,
        )
    assert not (tmp_path / "image-provenance.json").exists()


@pytest.mark.parametrize(
    "case",
    (
        "missing-env",
        "duplicate-env",
        "extra-label",
        "missing-digest-metadata",
        "entrypoint",
        "command",
        "working-directory",
        "python-path",
    ),
)
def test_image_build_fails_closed_on_incomplete_or_ambiguous_metadata(
    tmp_path: Path, case: str
) -> None:
    source_context = _minimal_source_context(tmp_path / "source")
    lock_path = source_context / "containers/p6/runtime-lock.json"
    containerfile = source_context / "containers/p6/Containerfile"
    _, lock_sha = load_runtime_lock(lock_path)
    base = ImageBuildRuntime(
        lock_sha=lock_sha,
        containerfile_sha=hashlib.sha256(containerfile.read_bytes()).hexdigest(),
        git_revision="6" * 40,
    )

    def corrupt_inspect(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = base(argv, **kwargs)
        if argv[1:3] != ["image", "inspect"]:
            return result
        rows = json.loads(result.stdout)
        inspect = rows[0]
        if case == "missing-env":
            del inspect["Config"]["Env"]
        elif case == "duplicate-env":
            inspect["Config"]["Env"].append("PATH=/attacker")
        elif case == "extra-label":
            inspect["Config"]["Labels"]["attacker"] = "injected"
        elif case == "missing-digest-metadata":
            del inspect["RepoDigests"]
        elif case == "entrypoint":
            inspect["Config"]["Entrypoint"] = ["/attacker"]
        elif case == "command":
            inspect["Config"]["Cmd"] = ["/attacker"]
        elif case == "working-directory":
            inspect["Config"]["WorkingDir"] = "/attacker"
        elif case == "python-path":
            inspect["Config"]["Env"].append("PYTHONPATH=/attacker")
        else:
            raise AssertionError(case)
        return _result(argv, rows)

    with pytest.raises(P6LocalRuntimeError):
        build_toolchain_image(
            runtime="podman",
            repository="zscope-p6",
            git_revision="6" * 40,
            lock_path=lock_path,
            containerfile=containerfile,
            context=source_context,
            output=tmp_path / "image-provenance.json",
            process_runner=corrupt_inspect,
        )
    assert not (tmp_path / "image-provenance.json").exists()


def test_image_provenance_publish_is_exclusive_under_output_race(tmp_path: Path) -> None:
    source_context = _minimal_source_context(tmp_path / "source")
    lock_path = source_context / "containers/p6/runtime-lock.json"
    containerfile = source_context / "containers/p6/Containerfile"
    _, lock_sha = load_runtime_lock(lock_path)
    output = tmp_path / "image-provenance.json"
    base = ImageBuildRuntime(
        lock_sha=lock_sha,
        containerfile_sha=hashlib.sha256(containerfile.read_bytes()).hexdigest(),
        git_revision="7" * 40,
    )

    def race_output(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = base(argv, **kwargs)
        if argv[1] == "run":
            output.write_bytes(b"attacker-owned-output\n")
        return result

    with pytest.raises(P6LocalRuntimeError, match="atomically"):
        build_toolchain_image(
            runtime="podman",
            repository="zscope-p6",
            git_revision="7" * 40,
            lock_path=lock_path,
            containerfile=containerfile,
            context=source_context,
            output=output,
            process_runner=race_output,
        )
    assert output.read_bytes() == b"attacker-owned-output\n"
    assert list(tmp_path.glob(".image-provenance.json.*.tmp")) == []


def _image_provenance(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    value: dict[str, Any] = {
        "schema_version": "zscope.p6-local-image-provenance.v1",
        "git_revision": "1" * 40,
        "platform": "linux/amd64",
        "base_image_ref": BASE_IMAGE_REF,
        "base_image_digest": BASE_IMAGE_DIGEST,
        "runtime_lock_sha256": "2" * 64,
        "containerfile_sha256": "3" * 64,
        "python_requirements_sha256": "4" * 64,
        "image_ref": "localhost/zscope-p6@sha256:" + "a" * 64,
        "image_digest": "sha256:" + "a" * 64,
        "image_id": "sha256:" + "b" * 64,
        "toolchain_probe": _toolchain_probe(),
        "credential_material_present": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    value["content_sha256"] = hashlib.sha256(body).hexdigest()
    path = tmp_path / "image-provenance.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path, value


class ProxyRuntime:
    def __init__(self, provenance: dict[str, Any]) -> None:
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []
        self.networks: dict[str, dict[str, Any]] = {}
        self.proxy: dict[str, Any] | None = None
        self.provenance = provenance
        self.live_relay: dict[str, Any] | None = None
        self.private_context_snapshots: list[dict[str, tuple[bool, tuple[str, ...]]]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = [str(value) for value in argv]
        self.commands.append(command)
        environment = dict(kwargs.get("env") or {})
        self.environments.append(environment)
        self.private_context_snapshots.append(
            {
                key: (Path(environment[key]).is_dir(), tuple(Path(environment[key]).iterdir()))
                for key in ("TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME")
            }
        )
        if command[1:3] == ["image", "inspect"]:
            return _result(
                command,
                [
                    {
                        "Id": self.provenance["image_id"],
                        "Digest": self.provenance["image_digest"],
                        "RepoDigests": [self.provenance["image_ref"]],
                        "Config": {
                            "Env": ["PATH=/usr/bin", "GPG_KEY=public"],
                            "Entrypoint": None,
                            "Cmd": ["python3", "--version"],
                            "WorkingDir": "/zscope-input",
                            "Labels": {
                                "org.opencontainers.image.base.digest": BASE_IMAGE_DIGEST,
                                "org.opencontainers.image.revision": self.provenance[
                                    "git_revision"
                                ],
                                "io.zscope.p6-runtime-lock-sha256": self.provenance[
                                    "runtime_lock_sha256"
                                ],
                                "io.zscope.p6-containerfile-sha256": self.provenance[
                                    "containerfile_sha256"
                                ],
                            },
                        },
                    }
                ],
            )
        if command[1:3] == ["network", "inspect"]:
            row = self.networks.get(command[3])
            return _result(command, [row], code=0) if row is not None else _result(command, code=1)
        if command[1:3] == ["network", "create"]:
            name = command[-1]
            labels = {
                command[index + 1].split("=", 1)[0]: command[index + 1].split("=", 1)[1]
                for index, item in enumerate(command[:-1])
                if item == "--label"
            }
            self.networks[name] = {
                "Name": name,
                "Internal": "--internal" in command,
                "Labels": labels,
            }
            return _result(command)
        if command[1] == "inspect":
            return (
                _result(command, [self.proxy], code=0)
                if self.proxy is not None
                else _result(command, code=1)
            )
        if command[1] == "run":
            labels = {
                command[index + 1].split("=", 1)[0]: command[index + 1].split("=", 1)[1]
                for index, item in enumerate(command[:-1])
                if item == "--label"
            }
            assert command[command.index("--network") + 1] == "none"
            mount = command[command.index("--mount") + 1]
            mount_parts = {
                item.split("=", 1)[0]: item.split("=", 1)[1]
                for item in mount.split(",")
                if "=" in item
            }
            image_index = command.index(self.provenance["image_ref"])
            image_labels = {
                "org.opencontainers.image.base.digest": BASE_IMAGE_DIGEST,
                "org.opencontainers.image.revision": self.provenance["git_revision"],
                "io.zscope.p6-runtime-lock-sha256": self.provenance["runtime_lock_sha256"],
                "io.zscope.p6-containerfile-sha256": self.provenance["containerfile_sha256"],
            }
            self.proxy = {
                "Id": "c" * 64,
                "Image": self.provenance["image_id"],
                "ImageName": self.provenance["image_ref"],
                "Path": command[image_index + 1],
                "Args": command[image_index + 2 :],
                "Config": {
                    "Image": self.provenance["image_ref"],
                    "Labels": {**image_labels, **labels},
                    "Env": ["PATH=/usr/bin"],
                    "User": "65532:65532",
                },
                "HostConfig": {
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "SecurityOpt": ["no-new-privileges"],
                    "PidsLimit": 64,
                    "CapDrop": ["CAP_ALL"],
                    "CapAdd": ["CAP_NET_BIND_SERVICE"],
                    "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
                    "LogConfig": {"Type": "none", "Config": {}},
                },
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": mount_parts["src"],
                        "Destination": mount_parts["dst"],
                        "RW": False,
                    }
                ],
                "State": {"Running": True},
                "NetworkSettings": {"Networks": {}},
            }
            relay = Path(mount_parts["src"])
            relay_stat = relay.stat()
            self.live_relay = {
                "schema_version": "zscope.p6-relay-live-probe.v1",
                "destination": "/opt/zscope/p6_tcp_relay.py",
                "device": relay_stat.st_dev,
                "inode": relay_stat.st_ino,
                "mode": relay_stat.st_mode & 0o777,
                "sha256": hashlib.sha256(relay.read_bytes()).hexdigest(),
                "size": relay_stat.st_size,
            }
            return _result(command)
        if command[1] == "exec":
            assert self.proxy is not None
            assert command[2] == self.proxy["Id"]
            assert self.live_relay is not None
            return _result(command, self.live_relay)
        if command[1:3] == ["network", "connect"]:
            assert self.proxy is not None
            alias = command[command.index("--alias") + 1]
            network = command[-2]
            self.proxy["NetworkSettings"]["Networks"][network] = {"Aliases": [alias]}
            return _result(command)
        raise AssertionError(command)


def _provider() -> ProviderRuntimeContract:
    return ProviderRuntimeContract(
        base_url="https://api.example.test/v1",
        model="deepseek-v4-flash",
        response_model="deepseek-v4-flash-ga-260731",
        config_sha256="1" * 64,
        required_environment_keys=("Z_SCOPE_API_KEY",),
        identity_sha256="2" * 64,
    )


def test_proxy_provisioning_is_exact_credential_free_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = REPO_ROOT / "scripts/p6_tcp_relay.py"
    provenance_path, provenance = _image_provenance(tmp_path)
    assert load_image_provenance(provenance_path)["base_image_digest"] == BASE_IMAGE_DIGEST
    runtime = ProxyRuntime(provenance)
    sensitive_keys = {
        "GH_PAT",
        "GITHUB_PAT",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AZURE_CLIENT_ID",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "GROUND_TRUTH_CANARY",
    }
    for key in sensitive_keys:
        monkeypatch.setenv(key, "must-not-cross-proxy-boundary")
    monkeypatch.setenv("ZSCOPE_SAFE_PROXY_CANARY", "must-not-cross-proxy-boundary")
    monkeypatch.setenv("LD_LIBRARY_PATH", "C:/attacker-libraries")
    monkeypatch.setenv("ALL_PROXY", "http://attacker.invalid")
    monkeypatch.setenv("HOME", "C:/attacker-home")
    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref="localhost/zscope-p6@sha256:" + "a" * 64,
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=relay,
        image_provenance_path=provenance_path,
    )
    first = provision_transparent_proxy(
        request=request,
        provider_contract=_provider(),
        output=tmp_path / "proxy-1.json",
        process_runner=runtime,
        address_resolver=lambda _host, port: (("203.0.113.7", port), ("2001:db8::7", port)),
    )
    mutation_count = sum(
        command[1:3] in (["network", "create"], ["network", "connect"]) or command[1] == "run"
        for command in runtime.commands
    )
    second = provision_transparent_proxy(
        request=request,
        provider_contract=_provider(),
        output=tmp_path / "proxy-2.json",
        process_runner=runtime,
        address_resolver=lambda _host, port: (("203.0.113.7", port), ("2001:db8::7", port)),
    )

    run = next(command for command in runtime.commands if command[1] == "run")
    assert "--pull=never" in run and "--read-only" in run and "--log-driver=none" in run
    image_index = run.index(provenance["image_ref"])
    assert run[image_index + 1 : image_index + 4] == [
        "/usr/local/bin/python3",
        "-I",
        "-S",
    ]
    assert run[run.index("--unsetenv") + 1] == "GPG_KEY"
    assert "--env" not in run
    assert "Z_SCOPE_API_KEY" not in json.dumps(runtime.commands)
    mount = run[run.index("--mount") + 1]
    mounted_source = Path(
        next(item.split("=", 1)[1] for item in mount.split(",") if item.startswith("src="))
    )
    assert mounted_source != relay.resolve()
    assert mounted_source.parent.name.startswith("zscope-p6-relay-")
    assert mounted_source.read_bytes() == relay.read_bytes()
    assert first["relay_sha256"] == hashlib.sha256(mounted_source.read_bytes()).hexdigest()
    assert [run[index + 1] for index, item in enumerate(run[:-1]) if item == "--upstream"] == [
        "[2001:db8::7]:443",
        "203.0.113.7:443",
    ]
    internal_create = next(
        command
        for command in runtime.commands
        if command[1:3] == ["network", "create"] and "--internal" in command
    )
    assert "io.zscope.network-policy=model-endpoint-only" in internal_create
    assert first["credential_environment_keys"] == []
    assert first["upstream_count"] == 2
    assert second["created"] is False
    assert all(sensitive_keys.isdisjoint(environment) for environment in runtime.environments)
    assert all(
        set(environment)
        == {
            "HOME",
            "LANG",
            "PATH",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_RUNTIME_DIR",
        }
        for environment in runtime.environments
    )
    assert all("attacker" not in json.dumps(environment) for environment in runtime.environments)
    assert all(
        all(exists and rows == () for exists, rows in snapshot.values())
        for snapshot in runtime.private_context_snapshots
    )
    assert mutation_count == 5  # two networks, one proxy, two validated attachments
    assert (
        sum(
            command[1:3] in (["network", "create"], ["network", "connect"]) or command[1] == "run"
            for command in runtime.commands
        )
        == mutation_count
    )


def _write_expected_attestation_sources(
    tmp_path: Path,
) -> tuple[
    ProxyRuntime,
    ProxyProvisionRequest,
    Path,
    Path,
    dict[str, Any],
]:
    provenance_path, provenance = _image_provenance(tmp_path)
    runtime = ProxyRuntime(provenance)
    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref=provenance["image_ref"],
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=REPO_ROOT / "scripts/p6_tcp_relay.py",
        image_provenance_path=provenance_path,
    )
    proxy_path = tmp_path / "proxy-provision.json"
    provision = provision_transparent_proxy(
        request=request,
        provider_contract=_provider(),
        output=proxy_path,
        process_runner=runtime,
        address_resolver=lambda _host, port: (("203.0.113.7", port),),
    )
    candidate = str(provenance["git_revision"])
    lineage = {
        "workflow_run_id": "33260000001",
        "workflow_run_attempt": 2,
        "attempt_id": "p6-33260000001-2",
        "control_plane_commit": "c" * 40,
        "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "candidate_git_sha": candidate,
        "candidate_git_tree": "d" * 40,
        "provider_identity_sha256": _provider().identity_sha256,
        "image_ref": provenance["image_ref"],
        "image_id": provenance["image_id"],
        "proxy_container": request.proxy_container,
        "proxy_container_id": provision["proxy_container_id"],
        "network_name": request.internal_network,
        "egress_network_name": request.egress_network,
        "network_policy_sha256": provision["network_policy_sha256"],
        "endpoint_origin": provision["endpoint_origin"],
    }
    image_bytes = provenance_path.read_bytes()
    proxy_bytes = proxy_path.read_bytes()
    draft = {
        "schema_version": "zscope.p6-toolchain-oci-evidence.v1",
        "workflow_path": ".github/workflows/p6-pilot-validation.yml",
        "workflow_run_id": lineage["workflow_run_id"],
        "workflow_run_attempt": lineage["workflow_run_attempt"],
        "attempt_id": lineage["attempt_id"],
        "control_plane_commit": lineage["control_plane_commit"],
        "candidate_sha256": lineage["candidate_sha256"],
        "candidate_git_sha": lineage["candidate_git_sha"],
        "candidate_git_tree": lineage["candidate_git_tree"],
        "image_ref": provenance["image_ref"],
        "image_digest": provenance["image_digest"],
        "image_id": provenance["image_id"],
        "image_provenance_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "image_provenance_content_sha256": provenance["content_sha256"],
        "proxy_provision_sha256": hashlib.sha256(proxy_bytes).hexdigest(),
        "proxy_provision_content_sha256": provision["content_sha256"],
        "runtime_source_sha256": "e" * 64,
        "oci_execution_sha256": "f" * 64,
        "rootless_verified": True,
        "image_digest_verified": True,
        "mounts_verified": True,
        "network_restriction_verified": True,
        "runtime_source_mounted": True,
        "formal_evidence": False,
        "release_eligible": False,
    }
    toolchain = dict(seal_toolchain_evidence(draft))
    toolchain_path = tmp_path / "toolchain-evidence.json"
    toolchain_path.write_text(
        json.dumps(toolchain, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return runtime, request, toolchain_path, proxy_path, lineage


def test_expected_proxy_attestation_binds_frozen_receipts_and_live_identity(
    tmp_path: Path,
) -> None:
    runtime, request, toolchain_path, proxy_path, lineage = _write_expected_attestation_sources(
        tmp_path
    )
    output = tmp_path / "expected-proxy-attestation.json"
    value = build_expected_proxy_attestation(
        request=request,
        provider_contract=_provider(),
        toolchain_evidence_path=toolchain_path,
        proxy_provision_path=proxy_path,
        expected_lineage=lineage,
        output=output,
        process_runner=runtime,
    )
    file_sha = hashlib.sha256(output.read_bytes()).hexdigest()
    assert load_expected_proxy_attestation(output, expected_file_sha256=file_sha) == value
    assert value["schema_version"] == "zscope.p6-expected-proxy-attestation.v2"
    assert value["proxy_container_id"] == "c" * 64
    assert value["proxy_provision_sha256"] == hashlib.sha256(proxy_path.read_bytes()).hexdigest()
    assert value["network_names"] == ["zscope-p6-egress", "zscope-p6-internal"]
    assert value["credential_environment_keys"] == []


def test_bootstrap_proxy_attestation_is_strict_non_release_receipt_binding(
    tmp_path: Path,
) -> None:
    runtime, request, _toolchain_path, proxy_path, lineage = _write_expected_attestation_sources(
        tmp_path
    )
    assert runtime.proxy is not None
    value = build_bootstrap_proxy_attestation(
        request=request,
        provider_contract=_provider(),
        image_provenance_path=request.image_provenance_path,
        proxy_provision_path=proxy_path,
        expected_lineage={
            "workflow_run_id": lineage["workflow_run_id"],
            "workflow_run_attempt": lineage["workflow_run_attempt"],
            "attempt_id": lineage["attempt_id"],
            "repository": "local/zscope",
        },
    )

    assert value["schema_version"] == "zscope.p6-bootstrap-proxy-attestation.v1"
    assert value["bootstrap_preflight_only"] is True
    assert value["formal_evidence"] is False
    assert value["release_eligible"] is False
    assert value["credential_environment_keys"] == []
    assert (
        value["image_provenance_sha256"]
        == hashlib.sha256(request.image_provenance_path.read_bytes()).hexdigest()
    )
    assert value["proxy_provision_sha256"] == hashlib.sha256(proxy_path.read_bytes()).hexdigest()
    assert value["content_sha256"] == canonical_sha256(
        {key: item for key, item in value.items() if key != "content_sha256"}
    )


def test_bootstrap_proxy_attestation_fails_closed_on_receipt_or_lineage_drift(
    tmp_path: Path,
) -> None:
    _runtime, request, _toolchain_path, proxy_path, lineage = _write_expected_attestation_sources(
        tmp_path
    )
    proxy = json.loads(proxy_path.read_text(encoding="utf-8"))
    proxy["provider_identity_sha256"] = "f" * 64
    proxy["content_sha256"] = canonical_sha256(
        {key: value for key, value in proxy.items() if key != "content_sha256"}
    )
    proxy_path.write_text(json.dumps(proxy), encoding="utf-8")

    with pytest.raises(P6LocalRuntimeError, match="receipt lineage"):
        build_bootstrap_proxy_attestation(
            request=request,
            provider_contract=_provider(),
            image_provenance_path=request.image_provenance_path,
            proxy_provision_path=proxy_path,
            expected_lineage={
                "workflow_run_id": lineage["workflow_run_id"],
                "workflow_run_attempt": lineage["workflow_run_attempt"],
                "attempt_id": lineage["attempt_id"],
                "repository": "local/zscope",
            },
        )


def test_local_preflight_uses_bootstrap_then_revalidates_final_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _runtime, request, _old_toolchain, proxy_path, lineage = _write_expected_attestation_sources(
        tmp_path
    )
    image_provenance = load_image_provenance(request.image_provenance_path)
    proxy_provision = json.loads(proxy_path.read_text(encoding="utf-8"))
    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    toolchain_output = tmp_path / "fresh-toolchain.json"
    final_attestation_output = tmp_path / "fresh-final-attestation.json"
    executor_calls: list[dict[str, Any]] = []

    class FakeExecutor:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = dict(kwargs)
            executor_calls.append(self.kwargs)

        def preflight(self) -> dict[str, Any]:
            bootstrap = self.kwargs.get("bootstrap_expected_proxy_attestation")
            if bootstrap is not None:
                assert bootstrap["bootstrap_preflight_only"] is True
                return {"proxy_attestation_bootstrap_preflight_only": True}
            environment = self.kwargs["environment"]
            final_path = Path(environment["Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE"])
            assert final_path == final_attestation_output
            assert environment["Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256"] == (
                hashlib.sha256(final_path.read_bytes()).hexdigest()
            )
            return {
                "proxy_attestation_file_sha256": hashlib.sha256(
                    final_path.read_bytes()
                ).hexdigest(),
                "proxy_attestation_content_sha256": "9" * 64,
                "proxy_container_id": proxy_provision["proxy_container_id"],
            }

        def execute_phase(
            self,
            phase: str,
            command: tuple[str, ...],
            *,
            log_path: Path,
            accepted_returncodes: tuple[int, ...],
            provider_credentials: bool,
        ) -> None:
            assert phase == "preflight"
            assert command[0:2] == ("python3", "-c")
            assert log_path.name == "toolchain-phase.json"
            assert accepted_returncodes == (0,)
            assert provider_credentials is False

        def execution_evidence(self, *, required_phases: tuple[str, ...]) -> dict[str, Any]:
            assert required_phases == ("preflight",)
            return {
                "runtime_source_sha256": "e" * 64,
                "image_id": image_provenance["image_id"],
                "proxy_container_id": proxy_provision["proxy_container_id"],
                "network_policy_sha256": proxy_provision["network_policy_sha256"],
                "provider_identity_sha256": _provider().identity_sha256,
                "rootless_verified": True,
                "image_digest_verified": True,
                "mounts_verified": True,
                "network_restriction_verified": True,
                "runtime_source_mounted": True,
                "release_capable": False,
                "bootstrap_preflight_only": True,
            }

    def fake_git_value(_root: Path, revision: str) -> str:
        return "d" * 40 if revision == "HEAD^{tree}" else str(image_provenance["git_revision"])

    def fake_prepare_runtime_source(target: Path, *, git_revision: str) -> str:
        assert git_revision == image_provenance["git_revision"]
        target.mkdir(parents=True)
        (target / "__init__.py").write_text("\n", encoding="utf-8")
        return "e" * 64

    def fake_validate_execution(
        _execution: dict[str, Any], *, require_release_capable: bool
    ) -> list[str]:
        assert require_release_capable is False
        return []

    def fake_build_final(**kwargs: Any) -> dict[str, Any]:
        assert Path(kwargs["toolchain_evidence_path"]) == toolchain_output
        assert toolchain_output.is_file()
        payload = {"content_sha256": "9" * 64}
        Path(kwargs["output"]).write_text(json.dumps(payload), encoding="utf-8")
        return payload

    monkeypatch.setattr(p6_local_runtime_cli, "RootlessOciExecutor", FakeExecutor)
    monkeypatch.setattr(p6_local_runtime_cli, "_git_value", fake_git_value)
    monkeypatch.setattr(
        p6_local_runtime_cli, "prepare_p6_runtime_source", fake_prepare_runtime_source
    )
    monkeypatch.setattr(
        p6_local_runtime_cli, "require_p6_provider_contract", lambda _path: _provider()
    )
    monkeypatch.setattr(
        p6_local_runtime_cli, "validate_oci_execution_evidence", fake_validate_execution
    )
    monkeypatch.setattr(p6_local_runtime_cli, "build_expected_proxy_attestation", fake_build_final)
    args = SimpleNamespace(
        control_plane_commit=lineage["control_plane_commit"],
        candidate_commit=image_provenance["git_revision"],
        workflow_run_id=lineage["workflow_run_id"],
        workflow_run_attempt=lineage["workflow_run_attempt"],
        attempt_id=lineage["attempt_id"],
        repository="local/zscope",
        image=image_provenance["image_ref"],
        toolchain_evidence=toolchain_output.absolute(),
        expected_proxy_attestation=final_attestation_output.absolute(),
        candidate_root=candidate_root,
        image_provenance=request.image_provenance_path,
        proxy_provision=proxy_path,
        config=tmp_path / "config.yaml",
        runtime="podman",
        network=request.internal_network,
        egress_network=request.egress_network,
        proxy_container=request.proxy_container,
        relay=request.relay_path,
    )

    assert p6_local_runtime_cli._preflight(args) == 0
    assert len(executor_calls) == 2
    assert (
        executor_calls[0]["bootstrap_expected_proxy_attestation"]["bootstrap_preflight_only"]
        is True
    )
    assert "bootstrap_expected_proxy_attestation" not in executor_calls[1]


@pytest.mark.parametrize("case", ("same-name-id", "image", "command", "network", "relay"))
def test_expected_proxy_attestation_rejects_cross_job_live_drift(
    tmp_path: Path,
    case: str,
) -> None:
    runtime, request, toolchain_path, proxy_path, lineage = _write_expected_attestation_sources(
        tmp_path
    )
    assert runtime.proxy is not None
    runtime.proxy = copy.deepcopy(runtime.proxy)
    if case == "same-name-id":
        runtime.proxy["Id"] = "d" * 64
    elif case == "image":
        runtime.proxy["Image"] = "sha256:" + "f" * 64
    elif case == "command":
        runtime.proxy["Args"].append("--unexpected")
    elif case == "network":
        runtime.proxy["NetworkSettings"]["Networks"]["zscope-p6-internal"]["Aliases"] = [
            "attacker.invalid"
        ]
    elif case == "relay":
        relay = Path(runtime.proxy["Mounts"][0]["Source"])
        os.chmod(relay, 0o644)
        relay.write_bytes(b"attacker relay\n")
    else:
        raise AssertionError(case)
    with pytest.raises(P6LocalRuntimeError):
        build_expected_proxy_attestation(
            request=request,
            provider_contract=_provider(),
            toolchain_evidence_path=toolchain_path,
            proxy_provision_path=proxy_path,
            expected_lineage=lineage,
            output=tmp_path / f"expected-{case}.json",
            process_runner=runtime,
        )


def test_expected_proxy_attestation_rejects_old_incomplete_v1_receipt(
    tmp_path: Path,
) -> None:
    runtime, request, toolchain_path, proxy_path, lineage = _write_expected_attestation_sources(
        tmp_path
    )
    old = json.loads(proxy_path.read_text(encoding="utf-8"))
    old["schema_version"] = "zscope.p6-local-proxy-provision.v1"
    for field in (
        "image_id",
        "network_names",
        "network_aliases_sha256",
        "relay_projection_sha256",
        "command_projection_sha256",
        "expected_environment_sha256",
        "security_projection_sha256",
        "log_driver_projection_sha256",
        "image_inspect_projection_sha256",
        "proxy_inspect_projection_sha256",
    ):
        old.pop(field)
    old["content_sha256"] = canonical_sha256(
        {key: value for key, value in old.items() if key != "content_sha256"}
    )
    proxy_path.write_text(json.dumps(old), encoding="utf-8")
    with pytest.raises(P6LocalRuntimeError):
        build_expected_proxy_attestation(
            request=request,
            provider_contract=_provider(),
            toolchain_evidence_path=toolchain_path,
            proxy_provision_path=proxy_path,
            expected_lineage=lineage,
            output=tmp_path / "expected-old.json",
            process_runner=runtime,
        )


@pytest.mark.parametrize(
    "case",
    (
        "missing-env",
        "duplicate-env",
        "extra-label",
        "missing-digest-metadata",
        "entrypoint",
        "command",
        "working-directory",
    ),
)
def test_proxy_rejects_incomplete_or_ambiguous_image_metadata_before_mutation(
    tmp_path: Path, case: str
) -> None:
    provenance_path, provenance = _image_provenance(tmp_path)
    base = ProxyRuntime(provenance)

    def corrupt_inspect(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = base(argv, **kwargs)
        if argv[1:3] != ["image", "inspect"]:
            return result
        rows = json.loads(result.stdout)
        inspect = rows[0]
        if case == "missing-env":
            del inspect["Config"]["Env"]
        elif case == "duplicate-env":
            inspect["Config"]["Env"].append("PATH=/attacker")
        elif case == "extra-label":
            inspect["Config"]["Labels"]["attacker"] = "injected"
        elif case == "missing-digest-metadata":
            del inspect["RepoDigests"]
        elif case == "entrypoint":
            inspect["Config"]["Entrypoint"] = ["/attacker"]
        elif case == "command":
            inspect["Config"]["Cmd"] = ["/attacker"]
        elif case == "working-directory":
            inspect["Config"]["WorkingDir"] = "/attacker"
        else:
            raise AssertionError(case)
        return _result(argv, rows)

    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref=provenance["image_ref"],
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=REPO_ROOT / "scripts/p6_tcp_relay.py",
        image_provenance_path=provenance_path,
    )
    with pytest.raises(P6LocalRuntimeError):
        provision_transparent_proxy(
            request=request,
            provider_contract=_provider(),
            output=tmp_path / "proxy.json",
            process_runner=corrupt_inspect,
            address_resolver=lambda _host, port: (("203.0.113.7", port),),
        )
    assert not base.networks
    assert base.proxy is None
    assert not (tmp_path / "proxy.json").exists()


def test_proxy_fails_closed_if_private_relay_snapshot_changes_during_provision(
    tmp_path: Path,
) -> None:
    provenance_path, provenance = _image_provenance(tmp_path)
    base = ProxyRuntime(provenance)

    def mutate_relay(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = base(argv, **kwargs)
        if argv[1:3] == ["network", "connect"]:
            assert base.proxy is not None
            mounted = Path(base.proxy["Mounts"][0]["Source"])
            os.chmod(mounted, 0o644)
            mounted.write_bytes(b"attacker relay\n")
        return result

    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref=provenance["image_ref"],
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=REPO_ROOT / "scripts/p6_tcp_relay.py",
        image_provenance_path=provenance_path,
    )
    with pytest.raises(P6LocalRuntimeError, match="relay snapshot"):
        provision_transparent_proxy(
            request=request,
            provider_contract=_provider(),
            output=tmp_path / "proxy.json",
            process_runner=mutate_relay,
            address_resolver=lambda _host, port: (("203.0.113.7", port),),
        )
    assert not (tmp_path / "proxy.json").exists()


def test_proxy_fails_closed_on_bind_source_swap_restore(tmp_path: Path) -> None:
    provenance_path, provenance = _image_provenance(tmp_path)
    base = ProxyRuntime(provenance)

    def bind_attacker_then_restore(
        argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        if argv[1] != "run":
            return base(argv, **kwargs)
        mount = argv[argv.index("--mount") + 1]
        source = Path(
            next(item.split("=", 1)[1] for item in mount.split(",") if item.startswith("src="))
        )
        held = source.with_suffix(".held")
        os.rename(source, held)
        try:
            source.write_bytes(b"attacker relay\n")
            os.chmod(source, 0o444)
            return base(argv, **kwargs)
        finally:
            os.chmod(source, 0o600)
            source.unlink()
            os.rename(held, source)

    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref=provenance["image_ref"],
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=REPO_ROOT / "scripts/p6_tcp_relay.py",
        image_provenance_path=provenance_path,
    )
    with pytest.raises(P6LocalRuntimeError, match="live relay projection"):
        provision_transparent_proxy(
            request=request,
            provider_contract=_provider(),
            output=tmp_path / "proxy.json",
            process_runner=bind_attacker_then_restore,
            address_resolver=lambda _host, port: (("203.0.113.7", port),),
        )

    assert base.proxy is not None
    assert base.proxy["NetworkSettings"]["Networks"] == {}
    assert not (tmp_path / "proxy.json").exists()


def _corrupt_proxy(proxy: dict[str, Any], case: str) -> None:
    if case == "image-id":
        proxy["Image"] = "sha256:" + "f" * 64
    elif case == "image-name":
        proxy["ImageName"] = "localhost/attacker@sha256:" + "f" * 64
    elif case == "config-image":
        proxy["Config"]["Image"] = "localhost/attacker@sha256:" + "f" * 64
    elif case == "path":
        proxy["Path"] = "sh"
    elif case == "args":
        proxy["Args"].append("--unexpected")
    elif case == "state":
        proxy["State"]["Running"] = False
    elif case == "user":
        proxy["Config"]["User"] = "0:0"
    elif case == "credential-env":
        proxy["Config"]["Env"].append("GITHUB_PAT=credential-canary")
    elif case == "missing-env":
        del proxy["Config"]["Env"]
    elif case == "extra-env":
        proxy["Config"]["Env"].append("LANG=C.UTF-8")
    elif case == "extra-label":
        proxy["Config"]["Labels"]["attacker"] = "injected"
    elif case == "relay-projection":
        proxy["Config"]["Labels"]["io.zscope.relay-projection-sha256"] = "0" * 64
    elif case == "read-only-root":
        proxy["HostConfig"]["ReadonlyRootfs"] = False
    elif case == "privileged":
        proxy["HostConfig"]["Privileged"] = True
    elif case == "security-opt":
        proxy["HostConfig"]["SecurityOpt"] = []
    elif case == "pids":
        proxy["HostConfig"]["PidsLimit"] = 65
    elif case == "cap-drop":
        proxy["HostConfig"]["CapDrop"] = []
    elif case == "cap-add":
        proxy["HostConfig"]["CapAdd"] = ["CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"]
    elif case == "tmpfs":
        proxy["HostConfig"]["Tmpfs"]["/run"] = "rw,noexec,nosuid,nodev,size=16m"
    elif case == "log-driver":
        proxy["HostConfig"]["LogConfig"] = {"Type": "json-file", "Config": {}}
    elif case == "relay-read-write":
        proxy["Mounts"][0]["RW"] = True
    elif case == "relay-source":
        proxy["Mounts"][0]["Source"] = "C:/attacker-relay.py"
    elif case == "relay-destination":
        proxy["Mounts"][0]["Destination"] = "/opt/zscope/attacker.py"
    elif case == "extra-mount":
        proxy["Mounts"].append(
            {
                "Type": "bind",
                "Source": "C:/credential-store",
                "Destination": "/credential-store",
                "RW": False,
            }
        )
    elif case == "extra-network":
        proxy["NetworkSettings"]["Networks"]["attacker-network"] = {"Aliases": ["attacker"]}
    elif case == "internal-alias":
        proxy["NetworkSettings"]["Networks"]["zscope-p6-internal"]["Aliases"] = [
            "api.example.test",
            "unexpected",
        ]
    elif case == "egress-alias":
        proxy["NetworkSettings"]["Networks"]["zscope-p6-egress"]["Aliases"] = ["relay"]
    else:
        raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    (
        "image-id",
        "image-name",
        "config-image",
        "path",
        "args",
        "state",
        "user",
        "credential-env",
        "missing-env",
        "extra-env",
        "extra-label",
        "relay-projection",
        "read-only-root",
        "privileged",
        "security-opt",
        "pids",
        "cap-drop",
        "cap-add",
        "tmpfs",
        "log-driver",
        "relay-read-write",
        "relay-source",
        "relay-destination",
        "extra-mount",
        "extra-network",
        "internal-alias",
        "egress-alias",
    ),
)
def test_existing_proxy_fails_closed_on_any_runtime_identity_drift(
    tmp_path: Path, case: str
) -> None:
    provenance_path, provenance = _image_provenance(tmp_path)
    runtime = ProxyRuntime(provenance)
    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref=provenance["image_ref"],
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=REPO_ROOT / "scripts/p6_tcp_relay.py",
        image_provenance_path=provenance_path,
    )
    resolver = lambda _host, port: (("203.0.113.7", port),)
    provision_transparent_proxy(
        request=request,
        provider_contract=_provider(),
        output=tmp_path / "proxy-good.json",
        process_runner=runtime,
        address_resolver=resolver,
    )
    assert runtime.proxy is not None
    runtime.proxy = copy.deepcopy(runtime.proxy)
    _corrupt_proxy(runtime.proxy, case)
    mutation_count = sum(
        command[1:3] in (["network", "create"], ["network", "connect"]) or command[1] == "run"
        for command in runtime.commands
    )

    with pytest.raises(P6LocalRuntimeError):
        provision_transparent_proxy(
            request=request,
            provider_contract=_provider(),
            output=tmp_path / "proxy-rejected.json",
            process_runner=runtime,
            address_resolver=resolver,
        )
    assert not (tmp_path / "proxy-rejected.json").exists()
    assert (
        sum(
            command[1:3] in (["network", "create"], ["network", "connect"]) or command[1] == "run"
            for command in runtime.commands
        )
        == mutation_count
    )


def test_proxy_fails_closed_on_conflicting_existing_network(tmp_path: Path) -> None:
    provenance_path, provenance = _image_provenance(tmp_path)
    runtime = ProxyRuntime(provenance)
    runtime.networks["zscope-p6-internal"] = {
        "Internal": False,
        "Labels": {},
    }
    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref="localhost/zscope-p6@sha256:" + "a" * 64,
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=REPO_ROOT / "scripts/p6_tcp_relay.py",
        image_provenance_path=provenance_path,
    )

    with pytest.raises(P6LocalRuntimeError, match="conflicts"):
        provision_transparent_proxy(
            request=request,
            provider_contract=_provider(),
            output=tmp_path / "proxy.json",
            process_runner=runtime,
            address_resolver=lambda _host, port: (("203.0.113.7", port),),
        )
    assert not any(command[1] == "run" for command in runtime.commands)


def test_proxy_rejects_tampered_image_provenance_before_oci_mutation(tmp_path: Path) -> None:
    provenance_path, provenance = _image_provenance(tmp_path)
    provenance["image_digest"] = "sha256:" + "f" * 64
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    runtime = ProxyRuntime(provenance)
    request = ProxyProvisionRequest(
        runtime="podman",
        image_ref="localhost/zscope-p6@sha256:" + "a" * 64,
        internal_network="zscope-p6-internal",
        egress_network="zscope-p6-egress",
        proxy_container="zscope-p6-proxy",
        relay_path=REPO_ROOT / "scripts/p6_tcp_relay.py",
        image_provenance_path=provenance_path,
    )

    with pytest.raises(P6LocalRuntimeError, match="provenance"):
        provision_transparent_proxy(
            request=request,
            provider_contract=_provider(),
            output=tmp_path / "proxy.json",
            process_runner=runtime,
            address_resolver=lambda _host, port: (("203.0.113.7", port),),
        )
    assert runtime.commands == []


def test_image_provenance_probe_shape_is_closed_and_content_bound(tmp_path: Path) -> None:
    provenance_path, provenance = _image_provenance(tmp_path)
    assert load_image_provenance(provenance_path) == provenance

    tampered = json.loads(json.dumps(provenance))
    tampered["toolchain_probe"]["unexpected"] = "not permitted"
    unsigned = dict(tampered)
    unsigned.pop("content_sha256")
    tampered["content_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    provenance_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(P6LocalRuntimeError, match="toolchain probe"):
        load_image_provenance(provenance_path)

    schema = json.loads(
        (REPO_ROOT / "zscope/benchmarking/p6_local_image_provenance.schema.json").read_text(
            encoding="utf-8"
        )
    )
    open_objects: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                open_objects.append(path)
            for name, child in value.items():
                visit(child, f"{path}.{name}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(schema, "$")
    assert open_objects == []


class _Writer:
    def __init__(self) -> None:
        self.payload = bytearray()
        self.eof = False

    def write(self, value: bytes) -> None:
        self.payload.extend(value)

    async def drain(self) -> None:
        return None

    def write_eof(self) -> None:
        self.eof = True


def test_relay_accepts_only_literal_ips_and_forwards_tls_bytes_unchanged() -> None:
    assert p6_tcp_relay._upstream("203.0.113.7:443") == ("203.0.113.7", 443)
    assert p6_tcp_relay._upstream("[2001:db8::7]:443") == ("2001:db8::7", 443)
    with pytest.raises(Exception, match="IP:port"):
        p6_tcp_relay._upstream("api.example.test:443")

    payload = b"\x16\x03\x03\x00\x08opaque\x00tls"
    writer = _Writer()

    async def forward() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(payload)
        reader.feed_eof()
        await p6_tcp_relay._pipe(reader, writer)  # type: ignore[arg-type]

    asyncio.run(forward())
    assert bytes(writer.payload) == payload
    assert writer.eof is True
