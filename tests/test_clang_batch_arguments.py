"""Argument compatibility requires real compiler diagnostics, not stderr matching."""

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.retrieval import clang_batch
from zscope.retrieval.clang_backend import ClangBackend


@pytest.fixture
def native_indexer():
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native argument tests require Z_SCOPE_TEST_CLANG_INDEXER")
    return executable


def invoke(executable, root, options, source="int f(void) { return 1; }\n"):
    path = root / "test.c"
    path.write_text(source, encoding="utf-8")
    command = ["clang", *options, "-c", str(path)]
    job = root / "job.json"
    job.write_text(
        json.dumps(
            {"root": str(root), "directory": str(root), "source": str(path), "arguments": command}
        ),
        encoding="utf-8",
    )
    artifact = root / "facts.jsonl"
    process = subprocess.run(
        [executable, "--job", str(job), "--output", str(artifact)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    rows = (
        [json.loads(line) for line in artifact.read_text().splitlines()]
        if artifact.exists()
        else []
    )
    assert json.loads(job.read_text())["arguments"] == command
    return process, rows


@pytest.mark.parametrize("forwarded", [[], ["-Xpreprocessor", "-Werror"], ["-Wp,-Werror"]])
def test_warning_promotion_is_removed_before_first_attempt(native_indexer, tmp_path, forwarded):
    options = [
        "-Werror",
        "-Werror=unused-variable",
        "-Werror=unknown-warning-option",
        "-Wfake-warning",
    ]
    result, rows = invoke(
        native_indexer,
        tmp_path,
        options + forwarded,
        "#warning allowed during scanning\nint f(void) { int unused; return 1; }\n",
    )
    assert result.returncode == 0, result.stderr
    assert "warning:" in result.stderr
    policy = rows[-1]["argument_adjustments"]
    assert policy["ignored_warning_errors"] == options[:3] + (["-Werror"] if forwarded else [])
    assert "-Wunused-variable" in policy["effective_arguments"]
    assert len(policy["attempts"]) == 1
    assert policy["attempts"][0]["error_count"] == 0
    assert policy["attempts"][0]["warning_count"] > 0


def test_response_files_and_forwarded_options_preserve_include_values(native_indexer, tmp_path):
    includes = tmp_path / "-Werror"
    includes.mkdir()
    (includes / "kept.h").write_text("#define KEPT 7\n", encoding="utf-8")
    inner = tmp_path / "inner.rsp"
    inner.write_text(
        "-I -Werror -DNOTE=-Werror -Werror=unused-variable -fconserve-stack", encoding="utf-8"
    )
    outer = tmp_path / "outer.rsp"
    outer.write_text(
        "@inner.rsp -Xclang -Werror -Xclang -funknown-forwarded-option", encoding="utf-8"
    )
    before = (inner.read_bytes(), outer.read_bytes())
    result, rows = invoke(
        native_indexer,
        tmp_path,
        ["@outer.rsp"],
        '#include "kept.h"\nint f(void) { int unused; return KEPT; }\n',
    )
    assert result.returncode == 0, result.stderr
    policy = rows[-1]["argument_adjustments"]
    assert set(policy["removed_unknown_options"]) == {
        "-fconserve-stack",
        "-funknown-forwarded-option",
    }
    assert len(policy["attempts"]) == 2
    args = policy["effective_arguments"]
    assert args[args.index("-I") + 1] == "-Werror"
    assert "-DNOTE=-Werror" in args
    assert "-Xclang" not in args
    assert before == (inner.read_bytes(), outer.read_bytes())


@pytest.mark.parametrize("forwarding", ["-Xclang", "-Xpreprocessor"])
def test_forwarded_include_operand_is_not_a_warning_flag(native_indexer, tmp_path, forwarding):
    includes = tmp_path / "-Werror"
    includes.mkdir()
    (includes / "kept.h").write_text("#define KEPT 1\n", encoding="utf-8")
    result, rows = invoke(
        native_indexer,
        tmp_path,
        [forwarding, "-I", forwarding, "-Werror", forwarding, "-Werror"],
        '#include "kept.h"\n#warning allowed\nint f(void) { return KEPT; }\n',
    )
    assert result.returncode == 0, result.stderr
    policy = rows[-1]["argument_adjustments"]
    assert policy["ignored_warning_errors"] == ["-Werror"]
    assert policy["effective_arguments"][1:5] == [forwarding, "-I", forwarding, "-Werror"]


def test_comma_forwarding_preserves_operands_and_retries_unknowns(native_indexer, tmp_path):
    includes = tmp_path / "-Werror"
    includes.mkdir()
    (includes / "kept.h").write_text("#define KEPT 1\n", encoding="utf-8")
    result, rows = invoke(
        native_indexer,
        tmp_path,
        ["-Wp,-I,-Werror,-Werror,-funknown-cpp-option"],
        '#include "kept.h"\n#warning allowed\nint f(void) { return KEPT; }\n',
    )
    assert result.returncode == 0, result.stderr
    policy = rows[-1]["argument_adjustments"]
    assert policy["ignored_warning_errors"] == ["-Werror"]
    assert policy["removed_unknown_options"] == ["-funknown-cpp-option"]
    assert policy["effective_arguments"][1] == "-Wp,-I,-Werror"
    assert len(policy["attempts"]) == 2


@pytest.mark.parametrize(
    "options",
    [
        ["-fconserve-stack", "--zscope-fake-option", "-funknown-joined=value"],
        ["-fsynta-only"],  # Clang's diagnostic with a spelling suggestion.
        ["-Xclang", "-funknown-frontend-option"],
        ["-Xclang=-funknown-frontend-option"],
        ["-Xpreprocessor", "-funknown-frontend-option"],
    ],
)
def test_unknown_options_retry_once_with_fresh_facts(native_indexer, tmp_path, options):
    result, rows = invoke(native_indexer, tmp_path, options)
    assert result.returncode == 0, result.stderr
    assert rows[-1]["success"]
    policy = rows[-1]["argument_adjustments"]
    assert len(policy["attempts"]) == 2
    assert policy["attempts"][0]["error_count"] > 0
    assert policy["attempts"][1]["error_count"] == 0
    assert all(option not in policy["effective_arguments"] for option in options)
    assert result.stderr.count("[clang-batch-arguments] retry=1") == 1
    assert sum(row["kind"] == "header" for row in rows) == 1
    assert sum(row["kind"] == "function" for row in rows) == 1
    assert sum(row["kind"] == "complete" for row in rows) == 1


@pytest.mark.parametrize(
    "options,source",
    [
        (["-funknown-option"], "int f(void) { return missing_identifier; }\n"),
        (["-funknown-option", "-target", "invalid-zscope-triple"], "int f(void) { return 1; }\n"),
        (["-funknown-option", "missing-option-value"], "int f(void) { return 1; }\n"),
    ],
)
def test_retry_still_fails_on_real_errors_without_third_attempt(
    native_indexer, tmp_path, options, source
):
    result, rows = invoke(native_indexer, tmp_path, options, source)
    assert result.returncode != 0
    assert not rows[-1]["success"]
    policy = rows[-1]["argument_adjustments"]
    assert len(policy["attempts"]) == 2
    assert policy["attempts"][-1]["error_count"] > 0
    assert policy["removed_unknown_options"] == ["-funknown-option"]
    assert all(option in policy["effective_arguments"] for option in options[1:])
    assert result.stderr.count("[clang-batch-arguments] retry=1") == 1


def test_source_diagnostic_text_does_not_authorize_option_removal(native_indexer, tmp_path):
    result, rows = invoke(
        native_indexer,
        tmp_path,
        ["-Werror", "-DKEEP=1"],
        "#error unknown argument: '-DKEEP=1'\nint f(void) { return KEEP; }\n",
    )
    assert result.returncode != 0
    policy = rows[-1]["argument_adjustments"]
    assert len(policy["attempts"]) == 1
    assert policy["removed_unknown_options"] == []
    assert "-DKEEP=1" in policy["effective_arguments"]


def test_missing_response_file_is_failure(native_indexer, tmp_path):
    result, _ = invoke(native_indexer, tmp_path, ["@absent.rsp"])
    assert result.returncode != 0
    assert "error:" in result.stderr


def test_adjusted_tu_cache_and_failed_retry_keep_old_published_facts(
    native_indexer, tmp_path, monkeypatch
):
    source = tmp_path / "test.c"
    source.write_text("int kept(void) { return 1; }\n", encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    command = ["clang", "-Werror", "-fconserve-stack", "-c", str(source)]
    cdb.write_text(
        json.dumps([{"directory": str(tmp_path), "file": str(source), "arguments": command}])
    )
    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=native_indexer, max_threads=1)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        cache = Path(backend.db._db_path).parent / "clang_batch_cache"
        report = json.loads((cache / "latest_run.json").read_text())
        assert report["argument_retries"] == 0 and report["compiled_tus"] == 1
        package = next(
            json.loads(p.read_text())
            for p in cache.glob("*.json")
            if "artifact_sha256" in p.read_text()
        )
        assert package["argument_adjustments"]["removed_unknown_options"] == []
        preparation = json.loads(Path(backend._compile_preparation.report_path).read_text())
        assert preparation["adjustments"][0]["removed_unknown_options"] == ["-fconserve-stack"]
        assert backend._run_full_extraction()
        report = json.loads((cache / "latest_run.json").read_text())
        assert report["reused_tus"] == 1 and report["argument_retries"] == 0
        source.write_text("int broken(void) { return missing_identifier; }\n", encoding="utf-8")
        assert not backend._run_full_extraction()
        report = json.loads((cache / "latest_run.json").read_text())
        assert not report["complete"] and report["argument_retries"] == 0
        assert len(report["failed_tus"]) == 1
        failure = report["failed_tus"][0]
        assert failure["source"] == str(source)
        assert len(failure["argument_adjustments"]["attempts"]) == 1
        assert "missing_identifier" in failure["reason"]
        assert "[clang-batch-arguments] retry=1" not in Path(failure["stderr_path"]).read_text()
        assert json.loads(cdb.read_text())[0]["arguments"] == ["clang", "-c", str(source)]
        assert backend.db._conn.execute("SELECT name FROM functions").fetchall()[0][0] == "kept"
    finally:
        backend.close()


@pytest.mark.parametrize(
    "version,accepted", [(None, False), (1, False), (clang_batch.ARGUMENT_POLICY_VERSION, True)]
)
def test_old_native_tool_is_not_silently_used(monkeypatch, caplog, version, accepted):
    monkeypatch.setattr(clang_batch.shutil, "which", lambda _: "/test/indexer")
    capability = {"protocol": clang_batch.PROTOCOL, "position_encoding": "utf-8"}
    if version is not None:
        capability["argument_policy_version"] = version
        capability["argument_policy_digest"] = clang_batch.POLICY_DIGEST
    monkeypatch.setattr(
        clang_batch.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(capability)),
    )
    assert bool(clang_batch.find_indexer("indexer")) == accepted
    if not accepted:
        assert "rebuild zscope-clang-indexer" in caplog.text


@pytest.mark.skipif(os.name == "nt", reason="Linux Clang driver symlink contract")
def test_development_build_keeps_cpp_driver_symlink(tmp_path, monkeypatch):
    from scripts import build_clang_indexer

    sdk = tmp_path / "llvm"
    (sdk / "bin").mkdir(parents=True)
    (sdk / "bin" / "clang").touch()
    (sdk / "bin" / "clang++").symlink_to("clang")
    monkeypatch.setattr(
        "sys.argv",
        ["build_clang_indexer", "--llvm-prefix", str(sdk), "--prefix", str(tmp_path / "install")],
    )
    commands = []
    monkeypatch.setattr(
        build_clang_indexer.subprocess, "run", lambda command, **kw: commands.append(command)
    )
    build_clang_indexer.main()
    assert f"-DCMAKE_CXX_COMPILER={sdk / 'bin' / 'clang++'}" in commands[0]
