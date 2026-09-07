from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from scripts.validate_p6_artifact_tree import (
    P6ArtifactTreeError,
    discover_regular_files,
    revalidate_regular_file,
)
from scripts.project_p6_entry_lineage import project_gate_lineage
from scripts import run_p6_cold_producer
from zscope.benchmarking.runner import BenchmarkError
from zscope.benchmarking.p6_producer_sandbox import (
    materialize_p6_host_producer_sandbox,
    p6_host_producer_child_environment,
)
from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    canonical_sha256,
    load_json_strict,
    sha256_file,
)


ENTRY_GATE = Path("docs/design/zscope-2.0-security-architecture/acceptance/p6-entry-gate.json")


def test_cold_host_process_uses_a_physical_answer_free_cwd_and_pythonpath(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    for relative in (
        "scripts/run_p6_cold_producer.py",
        "zscope/__init__.py",
        "zscope/_version.py",
        "zscope/benchmarking/__init__.py",
        "zscope/benchmarking/p6_producer_metrics.py",
        "zscope/benchmarking/p6_producer_package_init.py",
        "zscope/benchmarking/p6_producer_sandbox.py",
        "zscope/benchmarking/runner.py",
        "test/range/zscope.benchmark.yaml",
        "test/range/src/example.c",
    ):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source = Path(relative)
        target.write_bytes(source.read_bytes() if source.is_file() else b"placeholder\n")
    forbidden = {
        "test/range/benchmark/ground_truth.json": b"{}\n",
        "zscope/benchmarking/protocol.py": b"SCORER = True\n",
        "zscope/cli/benchmark.py": b"SCORER_ENTRY = True\n",
        "zscope/core/ground_truth.json": b"{}\n",
        "zscope/core/review_packets/proof.json": b"{}\n",
        "zscope/orchestration/hypothesis_hunter/qualification/qualification-artifact.v2.json": b"{}\n",
        ".github/evidence/p6/review/decision.json": b"{}\n",
        "zscope/benchmarking/postscore_trace.py": b"POSTSCORE = True\n",
    }
    for relative, payload in forbidden.items():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    for command in (
        ("git", "init", "--quiet"),
        ("git", "-c", "core.autocrlf=false", "add", "."),
        (
            "git",
            "-c",
            "user.name=P6 Test",
            "-c",
            "user.email=p6@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "candidate",
        ),
    ):
        subprocess.run(command, cwd=repository, check=True)
    candidate = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, text=True
    ).strip()
    sandbox = tmp_path / "producer-source"
    receipt = tmp_path / "producer-receipt.json"
    materialize_p6_host_producer_sandbox(
        repository_root=repository,
        candidate_commit=candidate,
        destination=sandbox,
        receipt_path=receipt,
    )

    for relative in forbidden:
        assert not (sandbox / relative).exists()
    environment = p6_host_producer_child_environment(
        {
            **os.environ,
            "GITHUB_WORKSPACE": str(tmp_path / "control"),
            "P6_CONTROL_ROOT": str(tmp_path / "control"),
            "P6_CANDIDATE_ROOT": str(tmp_path / "candidate"),
            "Z_SCOPE_BENCHMARK_TRUTH": str(tmp_path / "truth.json"),
            "GIT_DIR": str(repository / ".git"),
            "GIT_WORK_TREE": str(repository),
            "GIT_INDEX_FILE": str(repository / ".git/index"),
            "GIT_OBJECT_DIRECTORY": str(repository / ".git/objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repository / ".git/objects"),
            "GIT_COMMON_DIR": str(repository / ".git"),
            "PWD": str(repository),
            "OLDPWD": str(tmp_path),
            "INIT_CWD": str(repository),
            "RUNNER_WORKSPACE": str(tmp_path),
            "CUSTOM_WORKSPACE_LOCATOR": str(repository / "test/range"),
            "Z_SCOPE_P6_CANDIDATE_COMMIT": candidate,
        },
        sandbox_root=sandbox,
        receipt_path=receipt,
        forbidden_roots=(repository,),
    )
    probe = (
        "import json,os,sys; from pathlib import Path; "
        "from zscope.benchmarking.p6_producer_sandbox import "
        "validate_p6_host_producer_sandbox; root=Path(os.environ["
        "'Z_SCOPE_P6_HOST_PRODUCER_ROOT']); receipt=Path(os.environ["
        "'Z_SCOPE_P6_HOST_PRODUCER_RECEIPT']); value="
        "validate_p6_host_producer_sandbox(sandbox_root=root,receipt_path=receipt,"
        "expected_candidate_commit=os.environ['Z_SCOPE_P6_CANDIDATE_COMMIT']); "
        "print(json.dumps({'cwd':str(Path.cwd()),'pythonpath':os.environ['PYTHONPATH'],"
        "'scorer':(root/'zscope/benchmarking/protocol.py').exists(),"
        "'truth':(root/'test/range/benchmark/ground_truth.json').exists(),"
        "'schema':value['schema_version']}))"
    )
    completed = subprocess.run(
        (sys.executable, "-c", probe),
        cwd=sandbox,
        env=environment,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    observed = json.loads(completed.stdout)
    assert observed == {
        "cwd": str(sandbox.resolve()),
        "pythonpath": str(sandbox.resolve()),
        "scorer": False,
        "truth": False,
        "schema": "zscope.p6-host-producer-sandbox.v1",
    }
    assert "GITHUB_WORKSPACE" not in environment
    assert "P6_CONTROL_ROOT" not in environment
    assert "P6_CANDIDATE_ROOT" not in environment
    assert "Z_SCOPE_BENCHMARK_TRUTH" not in environment
    assert not any(key.upper().startswith("GIT_") for key in environment)
    for key in (
        "PWD",
        "OLDPWD",
        "INIT_CWD",
        "RUNNER_WORKSPACE",
        "CUSTOM_WORKSPACE_LOCATOR",
    ):
        assert key not in environment
    git_probe = subprocess.run(
        ("git", "rev-parse", "--show-toplevel"),
        cwd=sandbox,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert git_probe.returncode != 0
    assert git_probe.stdout == ""


def test_cold_wrapper_enters_host_sandbox_before_importing_benchmark_runner() -> None:
    wrapper = Path("scripts/run_p6_cold_producer.py").read_text(encoding="utf-8")
    runner = Path("zscope/benchmarking/runner.py").read_text(encoding="utf-8")

    assert "materialize_p6_host_producer_sandbox(" in wrapper
    assert "cwd=str(sandbox)" in wrapper
    assert "p6_host_producer_child_environment(" in wrapper
    assert "forbidden_roots=(source_root,)" in wrapper
    assert 'launch_environment["Z_SCOPE_P6_API_KEY_FILE"]' in wrapper
    assert "str(private_output)" in wrapper
    assert "from zscope.benchmarking.runner import BenchmarkError, run_benchmark" not in wrapper
    assert (
        "from zscope.benchmarking.protocol import (" not in runner.split("def score_artifact", 1)[0]
    )


@pytest.mark.parametrize("child_returncode", [0, 2, "raise"])
def test_cold_launcher_does_not_pass_control_checkout_locators_to_actual_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    child_returncode: int | str,
) -> None:
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    control = tmp_path / "control"
    script = control / "scripts/run_p6_cold_producer.py"
    script.parent.mkdir(parents=True)
    script.write_text("# launcher\n", encoding="utf-8")
    key_file = control / "test/range/zscope.local.env"
    key_file.parent.mkdir(parents=True)
    key_file.write_text("Z_SCOPE_API_KEY=private\n", encoding="utf-8")
    attestation = control / "expected-proxy-attestation.json"
    attestation.write_text("{}\n", encoding="utf-8")
    if os.name == "posix":
        key_file.chmod(0o600)
        attestation.chmod(0o600)
    requested_output = control / "p6-balanced"
    marker = runner_temp / "p6-cold-balanced-failure.json"
    candidate = "a" * 40
    captured: dict[str, object] = {}

    def fake_materialize(**kwargs: object) -> dict[str, object]:
        destination = Path(str(kwargs["destination"]))
        receipt = Path(str(kwargs["receipt_path"]))
        (destination / "scripts").mkdir(parents=True)
        (destination / "scripts/run_p6_cold_producer.py").write_text("# child\n", encoding="utf-8")
        receipt.write_text("{}\n", encoding="utf-8")
        return {}

    def fake_child(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
        stdin: object,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        del stdin, check
        captured.update(command=list(command), cwd=cwd, environment=dict(env))
        if child_returncode == "raise":
            raise OSError("synthetic child launch failure")
        if child_returncode == 0:
            private_output = Path(command[command.index("--output") + 1])
            private_output.mkdir()
            (private_output / "aggregate.json").write_text("{}\n", encoding="utf-8")
        else:
            marker.write_text(
                '{"failure_class":"internal_failure","failure_count":1}\n',
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, int(child_returncode))

    monkeypatch.setattr(run_p6_cold_producer, "__file__", str(script))
    monkeypatch.setattr(
        run_p6_cold_producer,
        "materialize_p6_host_producer_sandbox",
        fake_materialize,
    )
    monkeypatch.setattr(run_p6_cold_producer.subprocess, "run", fake_child)
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("Z_SCOPE_P6_CANDIDATE_COMMIT", candidate)
    monkeypatch.setenv("Z_SCOPE_P6_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE", str(attestation))
    monkeypatch.setenv(
        "Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_SHA256",
        sha256_file(attestation),
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(control))
    monkeypatch.setenv("P6_CONTROL_ROOT", str(control))
    monkeypatch.setenv("GIT_DIR", str(control / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(control))
    monkeypatch.setenv("CUSTOM_WORKSPACE_LOCATOR", str(control / "test/range"))

    invocation = run_p6_cold_producer.argparse.Namespace(
        scan_depth="balanced",
        output=requested_output,
        failure_marker=marker,
    )
    if child_returncode == "raise":
        with pytest.raises(OSError, match="synthetic child launch failure"):
            run_p6_cold_producer._run_from_answer_free_host_sandbox(invocation)
        result = None
    else:
        result = run_p6_cold_producer._run_from_answer_free_host_sandbox(invocation)

    if child_returncode != "raise":
        assert result == child_returncode
        assert (requested_output / "aggregate.json").is_file() is (child_returncode == 0)
    command = captured["command"]
    environment = captured["environment"]
    assert isinstance(command, list)
    assert isinstance(environment, dict)
    serialized_child_inputs = json.dumps(
        {"command": command, "environment": environment}, sort_keys=True
    )
    assert str(control) not in serialized_child_inputs
    assert str(requested_output) not in command
    assert not any(str(key).upper().startswith("GIT_") for key in environment)
    assert captured["cwd"] == environment["Z_SCOPE_P6_HOST_PRODUCER_ROOT"]
    assert environment["PYTHONPATH"] == captured["cwd"]
    assert Path(environment["Z_SCOPE_P6_API_KEY_FILE"]).parent == runner_temp
    assert (
        Path(environment["Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE"]).parent == runner_temp
    )
    assert not Path(environment["Z_SCOPE_P6_API_KEY_FILE"]).exists()
    assert not Path(environment["Z_SCOPE_BENCHMARK_EXPECTED_PROXY_ATTESTATION_FILE"]).exists()
    assert not any(path.name.endswith("-key.env") for path in runner_temp.iterdir())
    assert not any(path.name.endswith("-proxy.json") for path in runner_temp.iterdir())
    assert all(
        b"Z_SCOPE_API_KEY=private" not in path.read_bytes()
        for path in runner_temp.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def test_answer_free_host_tree_imports_runner_without_loading_scorer(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(
        Path("zscope"),
        repository / "zscope",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    (repository / "scripts").mkdir()
    shutil.copy2(
        Path("scripts/run_p6_cold_producer.py"),
        repository / "scripts/run_p6_cold_producer.py",
    )
    for relative in ("CMakeLists.txt", "README.md", "zscope.benchmark.yaml"):
        source = Path("test/range") / relative
        if source.is_file():
            target = repository / "test/range" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    for directory in ("src", "include", "internal"):
        source = Path("test/range") / directory
        if source.is_dir():
            shutil.copytree(source, repository / "test/range" / directory)
    qualification_output = (
        repository / "zscope/orchestration/p6-proof-promotion-qualification.v1.json"
    )
    status_output = repository / "zscope/orchestration/successor-runtime-review-status.v1.json"
    qualification_environment = dict(os.environ)
    qualification_environment["PYTHONPATH"] = str(repository)
    subprocess.run(
        (
            sys.executable,
            str(Path("scripts/qualify_p6_proof_promotion.py").resolve()),
            "--output",
            str(qualification_output),
            "--status-output",
            str(status_output),
        ),
        cwd=Path.cwd(),
        env=qualification_environment,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    for command in (
        ("git", "init", "--quiet"),
        ("git", "-c", "core.autocrlf=false", "add", "."),
        (
            "git",
            "-c",
            "user.name=P6 Test",
            "-c",
            "user.email=p6@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "candidate",
        ),
    ):
        subprocess.run(command, cwd=repository, check=True)
    candidate = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, text=True
    ).strip()
    sandbox = tmp_path / "producer-source"
    receipt = tmp_path / "producer-receipt.json"
    materialize_p6_host_producer_sandbox(
        repository_root=repository,
        candidate_commit=candidate,
        destination=sandbox,
        receipt_path=receipt,
    )
    environment = p6_host_producer_child_environment(
        {**os.environ, "Z_SCOPE_P6_CANDIDATE_COMMIT": candidate},
        sandbox_root=sandbox,
        receipt_path=receipt,
    )
    probe = (
        "import json,sys; from pathlib import Path; "
        "from zscope.benchmarking.runner import run_benchmark; root=Path.cwd(); "
        "from zscope.orchestration.proof_promotion_qualification import load_runtime_successor_qualification; successor=load_runtime_successor_qualification(); "
        "print(json.dumps({'callable':callable(run_benchmark),"
        "'successor_loaded':successor['status']=='local_candidate_qualified',"
        "'scorer_loaded':'zscope.benchmarking.protocol' in sys.modules,"
        "'scorer_present':(root/'zscope/benchmarking/protocol.py').exists(),"
        "'scorer_entry_present':(root/'zscope/cli/benchmark.py').exists(),"
        "'truth_present':(root/'test/range/benchmark').exists(),"
        "'qualification_present':(root/'zscope/orchestration/hypothesis_hunter/qualification/qualification-artifact.v2.json').exists(),"
        "'review_present':(root/'.github/evidence').exists(),"
        "'postscore_present':(root/'zscope/benchmarking/postscore_trace.py').exists()}))"
    )
    completed = subprocess.run(
        (sys.executable, "-B", "-c", probe),
        cwd=sandbox,
        env=environment,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    assert json.loads(completed.stdout) == {
        "callable": True,
        "successor_loaded": True,
        "scorer_loaded": False,
        "scorer_present": False,
        "scorer_entry_present": False,
        "truth_present": False,
        "qualification_present": False,
        "review_present": False,
        "postscore_present": False,
    }


def test_upload_tree_rejects_a_same_directory_symlink_alias(tmp_path: Path) -> None:
    control = tmp_path / "control"
    control.mkdir()
    target = control / "payload.json"
    target.write_text("{}\n", encoding="utf-8")
    alias = control / "alias.json"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(P6ArtifactTreeError, match="symbolic link"):
        discover_regular_files(control, [str(alias)])


def test_upload_tree_rejects_a_symlinked_directory_member(tmp_path: Path) -> None:
    control = tmp_path / "control"
    payload = control / "payload"
    payload.mkdir(parents=True)
    target = control / "target"
    target.mkdir()
    (target / "result.json").write_text("{}\n", encoding="utf-8")
    alias = payload / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(P6ArtifactTreeError, match="symbolic link"):
        discover_regular_files(control, [str(payload)])


def test_upload_tree_revalidates_the_exact_resolved_regular_member(
    tmp_path: Path,
) -> None:
    control = tmp_path / "control"
    control.mkdir()
    member = control / "payload.json"
    member.write_text("{}\n", encoding="utf-8")

    discovered = discover_regular_files(control, [str(member)])

    assert discovered == (member.resolve(strict=True),)
    assert revalidate_regular_file(control, discovered[0]) == member.resolve(strict=True)


def test_freeze_scans_all_run_bound_answer_material_canaries() -> None:
    protocol = Path("zscope/benchmarking/p6_protocol.py").read_text(encoding="utf-8")
    freeze_cli = Path("scripts/p6_balanced_orchestrator.py").read_text(encoding="utf-8")

    for category in (
        "source",
        "truth",
        "expected",
        "scorer",
        "prompt",
        "response",
        "model-output",
    ):
        assert f'"{category}"' in protocol
    assert "derive_p6_artifact_canaries(" in freeze_cli


@pytest.mark.parametrize(
    ("depth", "failure_class"),
    [
        ("fast", "provider_transport_exhausted"),
        ("balanced", "terminal_state_inconsistent"),
        ("deep", "queue_not_drained"),
    ],
)
def test_cold_producer_persists_only_the_typed_benchmark_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    depth: str,
    failure_class: str,
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    marker = tmp_path / f"p6-cold-{depth}-failure.json"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise BenchmarkError("private failure body", failure_class=failure_class)

    monkeypatch.setattr(run_p6_cold_producer, "run_benchmark", fail)

    assert (
        run_p6_cold_producer.run_cold_producer(
            scan_depth=depth,
            output=tmp_path / "output",
            failure_marker=marker,
            require_source_sandbox=False,
        )
        == 2
    )
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "failure_class": failure_class,
        "failure_count": 1,
    }
    assert "private" not in marker.read_text(encoding="utf-8")


def test_cold_producer_maps_unknown_exceptions_to_internal_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    marker = tmp_path / "p6-cold-fast-failure.json"
    monkeypatch.setattr(
        run_p6_cold_producer,
        "run_benchmark",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("secret body")),
    )

    assert (
        run_p6_cold_producer.run_cold_producer(
            scan_depth="fast",
            output=tmp_path / "output",
            failure_marker=marker,
            require_source_sandbox=False,
        )
        == 2
    )
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "failure_class": "internal_failure",
        "failure_count": 1,
    }
    assert "secret" not in marker.read_text(encoding="utf-8")


def test_cold_producer_forces_answer_free_scanning_before_external_freeze(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    observed: dict[str, object] = {}

    def succeed(*args: object, **kwargs: object) -> dict[str, object]:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return {}

    monkeypatch.setattr(run_p6_cold_producer, "run_benchmark", succeed)
    marker = tmp_path / "p6-cold-balanced-failure.json"

    assert (
        run_p6_cold_producer.run_cold_producer(
            scan_depth="balanced",
            output=tmp_path / "output",
            failure_marker=marker,
            require_source_sandbox=False,
        )
        == 0
    )
    assert observed["args"] == ("c_cpp", "pilot")
    assert observed["kwargs"] == {
        "runs": 1,
        "output": tmp_path / "output",
        "scan_depth": "balanced",
        "answer_free_producer": True,
    }
    assert not marker.exists()


def test_entry_lineage_projection_binds_the_exact_successful_e0_gate() -> None:
    gate = load_json_strict(ENTRY_GATE)
    projection = project_gate_lineage(gate, gate_file_sha256=sha256_file(ENTRY_GATE))

    assert projection["review"]["run_id"] == gate["e0_review"]["run_id"]
    assert projection["review"]["artifacts"] == {
        name: {
            "id": artifact["id"],
            "digest": artifact["digest"],
            "expired": False,
        }
        for name, artifact in sorted(gate["e0_review"]["artifacts"].items())
    }
    assert projection["attestation"]["artifact_id"] == (gate["e0_attestation"]["artifact"]["id"])
    assert projection["entry_gate_file_sha256"] == sha256_file(ENTRY_GATE)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("e0_review", "conclusion"), "failure"),
        (("e0_review", "artifacts", "pair", "expired"), True),
        (("review_packets", "unchanged"), False),
        (("ancestry", "scorer_is_ancestor_of_truth"), False),
    ],
)
def test_entry_lineage_projection_rejects_unattested_or_drifted_gate(
    path: tuple[str, ...], value: object
) -> None:
    gate = copy.deepcopy(load_json_strict(ENTRY_GATE))
    cursor = gate
    for name in path[:-1]:
        cursor = cursor[name]
    cursor[path[-1]] = value
    gate["content_sha256"] = canonical_sha256(
        {name: body for name, body in gate.items() if name != "content_sha256"}
    )

    with pytest.raises(P6ProtocolError):
        project_gate_lineage(gate, gate_file_sha256=sha256_file(ENTRY_GATE))
