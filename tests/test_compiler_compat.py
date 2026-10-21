import json
import os
import shutil
import subprocess
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

from zscope.retrieval import bitcode_compile
from zscope.retrieval.build_llvm import BitcodeBuilder
from zscope.retrieval.compiler_compat import (
    POLICY_DIGEST,
    POLICY_VERSION,
    adjust_arguments,
    expand_arguments,
    unknown_options,
)
from zscope.retrieval.indexing_runtime import MeasuredProcess
from zscope.retrieval.indexing_identity import command_identity, digest_json


CASES = [
    (["-Werror", "-Werror=unused-variable"], []),
    (
        ["-Werror", "-fconserve-stack", "-funknown-zscope-option"],
        ["-fconserve-stack", "-funknown-zscope-option"],
    ),
    (["-Xclang", "-Werror", "-Xclang", "-funknown-zscope-option"], ["-funknown-zscope-option"]),
    (["-Wp,-Werror,-funknown-zscope-option"], ["-funknown-zscope-option"]),
    (["@compat.rsp"], ["-funknown-zscope-option"]),
]


@pytest.mark.parametrize(
    "arguments,expected",
    [
        (["-I", "-Werror", "-DNOTE=-Werror", "-Werror"], ["-I", "-Werror", "-DNOTE=-Werror"]),
        (
            ["-Xclang", "-I", "-Xclang", "-Werror", "-Xclang", "-Werror"],
            ["-Xclang", "-I", "-Xclang", "-Werror"],
        ),
        (["-Wp,-I,-Werror,-Werror"], ["-Wp,-I,-Werror"]),
        (["-include", "-Wp,-Werror", "-Werror"], ["-include", "-Wp,-Werror"]),
        (["--", "-Werror"], ["--", "-Werror"]),
        (
            ["-mllvm", "-Werror", "-Werror=unused-variable"],
            ["-mllvm", "-Werror", "-Wunused-variable"],
        ),
    ],
)
def test_argument_boundaries(arguments, expected):
    original = ["clang", *arguments]
    assert adjust_arguments(original)[0] == ["clang", *expected]
    assert original == ["clang", *arguments]


def test_response_expansion_preserves_inputs_and_rejects_cycles(tmp_path):
    inner, outer = tmp_path / "inner.rsp", tmp_path / "outer.rsp"
    inner.write_text('-I "with space" -Werror')
    outer.write_text("@inner.rsp @inner.rsp")
    expanded = expand_arguments(["clang", "@outer.rsp"], tmp_path)
    assert expanded == ["clang", "-I", "with space", "-Werror", "-I", "with space", "-Werror"]
    assert inner.read_text() == '-I "with space" -Werror'
    inner.write_text("@outer.rsp")
    with pytest.raises(ValueError, match="recursive response"):
        expand_arguments(["clang", "@outer.rsp"], tmp_path)


def test_only_compiler_unknown_diagnostics_authorize_removal():
    args = ["clang", "-funknown", "-I", "-fvalue", "-DKEEP=1"]
    diagnostics = "\n".join(
        [
            "clang-18: error: unknown argument: '-funknown'",
            "test.c:1:2: error: unknown argument: '-DKEEP=1'",
            "    1 | #error unknown argument: '-DKEEP=1'",
            "gclang: error: unknown argument: '-DKEEP=1'",
            "clang: warning: unknown argument: '-DKEEP=1'",
            "clang: error: unknown argument: '-fvalue'",
        ]
    )
    assert unknown_options(diagnostics, args) == ["-funknown"]
    assert adjust_arguments(args, ["-funknown"])[0] == ["clang", "-I", "-fvalue", "-DKEEP=1"]


def builder_command(tmp_path, options, wrapper=False):
    source = tmp_path / "test.c"
    source.write_text("int f(void) { int unused; return 1; }\n")
    if "@compat.rsp" in options:
        includes = tmp_path / "-Werror"
        includes.mkdir()
        (includes / "kept.h").write_text("#define KEPT 7\n")
        (tmp_path / "compat.rsp").write_text(
            "-I -Werror -DNOTE=-Werror -Werror -funknown-zscope-option"
        )
        source.write_text('#include "kept.h"\nint f(void) { int unused; return KEPT; }\n')
    command = {
        "directory": str(tmp_path),
        "file": str(source),
        "arguments": [*(["ccache"] if wrapper else []), "clang", *options, "-c", str(source)],
    }
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([command]))
    output = tmp_path / "bc"
    output.mkdir()
    builder = BitcodeBuilder(tmp_path, cdb, output_dir=output, llvm_link_path="llvm-link-18")
    return builder, command, source


@pytest.mark.parametrize("failure", ["error", "timeout", "cancel"])
def test_retry_budget_and_failed_attempts_preserve_old_artifacts(tmp_path, monkeypatch, failure):
    builder, command, source = builder_command(tmp_path, ["-Werror", "-funknown"])
    context = digest_json(command_identity(command, tmp_path))
    final = builder.output_dir / f"tu_{context[:24]}_{source.stem}.o.bc"
    final.write_bytes(b"previous valid bitcode")
    monkeypatch.setattr(builder, "_matching_compiler", lambda cxx: "clang")
    monkeypatch.setattr(builder, "_tool_identity", lambda: {})
    calls = []
    clock = [100.0]
    monkeypatch.setattr(
        bitcode_compile, "time", SimpleNamespace(monotonic=lambda: clock[0], time_ns=time.time_ns)
    )

    def run(arguments, **kwargs):
        clock[0] += 0.5
        calls.append((list(arguments), kwargs))
        assert kwargs["env"]["LC_ALL"] == "C"
        output = Path(arguments[arguments.index("-o") + 1])
        assert not output.exists(), "a failed attempt must not leak into the next attempt"
        output.write_bytes(b"failed attempt")
        return MeasuredProcess(
            1,
            stderr="clang: error: unknown argument: '-funknown'",
            metrics={"timed_out": failure == "timeout", "cancelled": failure == "cancel"},
        )

    monkeypatch.setattr(bitcode_compile, "run_process", run)
    builder._compile_tu(command, 0)
    record = next(iter(builder._manifest["attempts"].values()))
    assert record["status"] == "failed" and not builder._bc_to_src
    assert final.read_bytes() == b"previous valid bitcode"
    assert len(calls) == (2 if failure == "error" else 1)
    assert "-Werror" not in calls[0][0]
    assert all(item[1]["timeout"] <= builder.timeout for item in calls)
    if len(calls) == 2:
        assert calls[1][1]["timeout"] < calls[0][1]["timeout"]
        assert "-funknown" not in calls[1][0]
        assert calls[0][1]["output_prefix"] != calls[1][1]["output_prefix"]


@pytest.mark.parametrize("options,removed", CASES)
@pytest.mark.parametrize("adapter", ["batch", "direct", "gllvm"])
def test_real_adapters_share_policy(tmp_path, options, removed, adapter):
    clang = shutil.which("clang-18") or shutil.which("clang")
    if not clang or os.name == "nt":
        pytest.skip("Linux Clang integration")
    native = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    gclang, get_bc = shutil.which("gclang"), shutil.which("get-bc")
    if adapter == "batch" and not native:
        pytest.skip("native indexer required")
    if adapter == "gllvm" and not (gclang and get_bc):
        pytest.skip("gllvm required")
    builder, command, source = builder_command(tmp_path, options, adapter == "gllvm")
    if adapter == "batch":
        job, output = tmp_path / "job.json", tmp_path / "facts.jsonl"
        job.write_text(
            json.dumps(
                {
                    "root": str(tmp_path),
                    "source": str(source),
                    "directory": str(tmp_path),
                    "arguments": command["arguments"],
                }
            )
        )
        result = subprocess.run(
            [native, "--job", str(job), "--output", str(output)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(output.read_text().splitlines()[-1])["argument_adjustments"]
    else:
        builder._compilers = {False: clang, True: clang}
        builder._env.update(
            LLVM_CC_NAME=clang, LLVM_CXX_NAME=clang, LLVM_COMPILER_PATH=str(Path(clang).parent)
        )
        builder.gclang, builder.get_bc = gclang or "gclang", get_bc or "get-bc"
        builder._compile_tu(command, 0)
        record = next(iter(builder._manifest["attempts"].values()))
        assert record["status"] == "compiled", record
        report = record["argument_adjustments"]
        assert len(builder._bc_to_src) == 1
        # Artifact, dependency and final argument evidence support a zero-compile restore.
        builder._compile_tu(command, 0)
        assert next(iter(builder._manifest["attempts"].values()))["status"] == "reused"
    assert report["policy_version"] == POLICY_VERSION
    assert report["policy_digest"] == POLICY_DIGEST
    assert sorted(set(report["removed_unknown_options"])) == sorted(removed)
    assert len(report["attempts"]) == (2 if removed else 1)


@pytest.mark.parametrize("adapter", ["direct", "gllvm"])
def test_real_bitcode_cache_policy_invalidation_and_source_failure(tmp_path, monkeypatch, adapter):
    clang = shutil.which("clang-18") or shutil.which("clang")
    if not clang or os.name == "nt":
        pytest.skip("Linux Clang integration")
    if adapter == "gllvm" and not (shutil.which("gclang") and shutil.which("get-bc")):
        pytest.skip("gllvm required")
    builder, command, source = builder_command(
        tmp_path, ["-funknown-zscope-option"], adapter == "gllvm"
    )
    builder._compilers = {False: clang, True: clang}
    builder.gclang, builder.get_bc = shutil.which("gclang"), shutil.which("get-bc")
    builder._compile_tu(command, 0)
    record = lambda: next(iter(builder._manifest["attempts"].values()))
    assert record()["status"] == "compiled", record()
    builder._compile_tu(command, 0)
    assert record()["status"] == "reused"
    monkeypatch.setattr(bitcode_compile, "POLICY_DIGEST", "changed-policy")
    builder._compile_tu(command, 0)
    assert record()["status"] == "compiled", record()
    final = Path(record()["bitcode"])
    previous = final.read_bytes()
    # As in build_groups, the new run only exports its successfully checked inputs.
    builder._bc_to_src.clear()
    source.write_text("#error unknown argument: '-DKEEP=1'\n")
    builder._compile_tu(command, 0)
    assert record()["status"] == "failed"
    assert not builder._bc_to_src and final.read_bytes() == previous
    assert len(record()["argument_adjustments"]["attempts"]) == 2
    assert record()["argument_adjustments"]["removed_unknown_options"] == [
        "-funknown-zscope-option"
    ]
