import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from zscope.retrieval import compile_commands_prepare as prep
from zscope.retrieval.compile_preflight import (
    CheckTool,
    preflight,
    probe_arguments,
    x86_64_arguments,
)
from zscope.retrieval.compiler_compat import adjust_arguments, expand_arguments
from zscope.retrieval.indexing_identity import executable_identity, search_directories_snapshot


def database(tmp_path, arguments, count=1):
    rows = [
        dict(
            directory=str(tmp_path),
            file=str(tmp_path / f"tu{i}.c"),
            output=f"tu{i}.o",
            arguments=["gcc", *arguments, "-c", str(tmp_path / f"tu{i}.c"), "-o", f"tu{i}.o"],
            custom={"variant": i},
        )
        for i in range(count)
    ]
    path = tmp_path / "compile_commands.json"
    path.write_text(json.dumps(rows))
    return path


@pytest.mark.parametrize(
    "options,expected",
    [
        (["-m32", "-m64", "-m32"], ["-m64", "-m64"]),
        (["-D", "-m32", "-I", "-m32", "-m32"], ["-D", "-m32", "-I", "-m32", "-m64"]),
        (
            ["-Xclang", "-D", "-Xclang", "-m32", "-m32"],
            ["-Xclang", "-D", "-Xclang", "-m32", "-m64"],
        ),
        (["--", "-m32"], ["--", "-m32"]),
        (["--target=aarch64-linux-gnu"], ["--target=aarch64-linux-gnu"]),
    ],
)
def test_architecture_option_boundaries(options, expected):
    assert x86_64_arguments(["clang", *options], "x86_64")[0] == ["clang", *expected]
    assert x86_64_arguments(["clang", "-m32"], "aarch64")[0] == ["clang", "-m32"]


@pytest.mark.parametrize(
    "args",
    [
        ["--target=i386-linux-gnu", "-m32"],
        ["-mx32"],
        ["--target=x86_64-linux-gnux32"],
        ["-m32", "-Xclang", "-triple", "-Xclang", "i386-linux-gnu"],
    ],
)
def test_conflicts_leave_original_untouched(tmp_path, args):
    path = database(tmp_path, args)
    original, stamp = path.read_bytes(), path.stat().st_mtime_ns
    with pytest.raises(ValueError, match="target conflict"):
        prep.prepare_compile_commands(path, [], host_arch="x86_64")
    assert path.read_bytes() == original and path.stat().st_mtime_ns == stamp


def test_all_warning_promotions_preserve_operands_and_normal_warnings():
    args = [
        "clang",
        "-Werror",
        "-Werror=unused-variable",
        "-Werror-implicit-function-declaration",
        "-pedantic-errors",
        "--pedantic-errors",
        "-Wall",
        "-Wp,-Werror,-D,VALUE",
        "-Wa,--fatal-warnings,--64",
        "-Wl,--fatal-warnings,-z,now",
        "-Xassembler",
        "--fatal-warnings",
        "-Xlinker",
        "-fatal_warnings",
        "-Xclang",
        "-I",
        "-Xclang",
        "-Werror",
        "-DVALUE=-Werror",
        "-mllvm",
        "-Werror",
    ]
    actual, changes = adjust_arguments(args)
    assert actual == [
        "clang",
        "-Wunused-variable",
        "-Wimplicit-function-declaration",
        "-pedantic",
        "-pedantic",
        "-Wall",
        "-Wp,-D,VALUE",
        "-Wa,--64",
        "-Wl,-z,now",
        "-Xclang",
        "-I",
        "-Xclang",
        "-Werror",
        "-DVALUE=-Werror",
        "-mllvm",
        "-Werror",
    ]
    assert len(changes["ignored_warning_errors"]) == 10


def test_response_backup_recovery_and_noop(tmp_path, monkeypatch):
    child = tmp_path / "nested file.rsp"
    child.write_text('-m32 -Werror -I "path with spaces"')
    outer = tmp_path / "outer.rsp"
    outer.write_text('@"nested file.rsp"')
    path = database(tmp_path, ["@outer.rsp"], 2)
    original = path.read_bytes()
    path.chmod(0o640)
    before = search_directories_snapshot([tmp_path])
    receipt = prep.prepare_compile_commands(path, [], host_arch="x86_64")
    assert path.stat().st_mode & 0o777 == 0o640
    backup = tmp_path / prep.MANAGED_DIRECTORY / "original" / (receipt.original_digest + ".json")
    assert backup.read_bytes() == original
    rows = json.loads(path.read_text())
    assert len(rows) == 2 and rows[1]["custom"] == {"variant": 1} and rows[1]["output"] == "tu1.o"
    assert any(arg.startswith("@") for arg in rows[0]["arguments"])
    assert "-m32" not in expand_arguments(rows[0]["arguments"], tmp_path)
    assert child.read_text().startswith("-m32 -Werror")
    assert search_directories_snapshot([tmp_path]) == before
    receipt.validate()
    stamp = path.stat().st_mtime_ns
    prep.prepare_compile_commands(path, [], host_arch="x86_64")
    assert path.stat().st_mtime_ns == stamp
    child.write_text("-m32 -Werror -DNEW=7")
    with pytest.raises(RuntimeError, match="changed"):
        receipt.validate()
    new = prep.prepare_compile_commands(path, [], host_arch="x86_64")
    assert new.original_digest == receipt.original_digest
    assert "-DNEW=7" in expand_arguments(json.loads(path.read_text())[0]["arguments"], tmp_path)
    assert backup.read_bytes() == original


@pytest.mark.parametrize("failure", ["backup", "readonly", "cycle", "concurrent", "response"])
def test_prepare_failures_never_publish(tmp_path, monkeypatch, failure):
    response = tmp_path / "args.rsp"
    response.write_text("-Werror")
    path = database(tmp_path, ["@args.rsp"])
    original = path.read_bytes()
    if failure == "readonly":
        path.chmod(0o444)
    elif failure == "cycle":
        response.write_text("@args.rsp")
    write = prep._write

    def intercept(target, data, **kwargs):
        if target.parent.name == "original":
            if failure == "backup":
                raise OSError("backup failed")
            if failure == "concurrent":
                path.write_text("[]")
            elif failure == "response":
                response.write_text("-DCHANGED=1")
        return write(target, data, **kwargs)

    monkeypatch.setattr(prep, "_write", intercept)
    with pytest.raises((OSError, ValueError, RuntimeError)):
        prep.prepare_compile_commands(path, [])
    assert path.read_bytes() == (b"[]" if failure == "concurrent" else original)


def test_symlink_and_concurrent_initializers(tmp_path):
    real = database(tmp_path, ["-Werror", "-m32"])
    alias = tmp_path / "link.json"
    alias.symlink_to(real.name)
    original = real.read_bytes()
    with ThreadPoolExecutor(4) as pool:
        receipts = list(
            pool.map(
                lambda p: prep.prepare_compile_commands(p, [], host_arch="x86_64"),
                [alias, real, alias, real],
            )
        )
    assert alias.is_symlink() and os.readlink(alias) == real.name
    assert len({r.original_digest for r in receipts}) == 1
    backup = (
        tmp_path / prep.MANAGED_DIRECTORY / "original" / (receipts[0].original_digest + ".json")
    )
    assert backup.read_bytes() == original


def test_command_to_arguments_and_context_dedup(tmp_path, monkeypatch):
    path = database(tmp_path, ["-Werror", "-funknown"], 100)
    rows = json.loads(path.read_text())
    import shlex

    rows[0]["command"] = shlex.join(rows[0].pop("arguments"))
    path.write_text(json.dumps(rows))
    calls = []

    def check(tool, args, directory, environment):
        calls.append(args)
        assert not any("tu" in arg for arg in args[1:])
        return dict(
            status="verified", removed_unknown_options=["-funknown"], targets=["x86_64-linux-gnu"]
        )

    monkeypatch.setattr(prep, "preflight", check)
    tool = CheckTool("clang", "missing-tool", identity={})
    receipt = prep.prepare_compile_commands(path, [tool])
    assert len(calls) == 1
    assert "command" not in json.loads(path.read_text())[0]
    assert "-funknown" not in path.read_text()
    prep.prepare_compile_commands(path, [tool])
    assert len(calls) == 1
    monkeypatch.setattr(prep, "POLICY_DIGEST", "next-policy")
    prep.prepare_compile_commands(path, [tool])
    assert len(calls) == 2 and "-funknown" in calls[-1]


def test_unverified_does_not_authorize_removal_or_persistent_check(tmp_path, monkeypatch):
    path = database(tmp_path, ["-funknown"])
    calls = []

    def check(*args):
        calls.append(1)
        return dict(status="unverified", removed_unknown_options=[], targets=[])

    monkeypatch.setattr(prep, "preflight", check)
    tool = CheckTool("clang", "missing")
    prep.prepare_compile_commands(path, [tool])
    prep.prepare_compile_commands(path, [tool])
    assert len(calls) == 2 and "-funknown" in path.read_text()


def test_shared_response_is_read_once_per_preparation(tmp_path, monkeypatch):
    response = tmp_path / "common.rsp"
    response.write_text("-Werror -DVALUE=1")
    path = database(tmp_path, ["@common.rsp"], 100)
    read = Path.read_bytes
    calls = []

    def counted(self):
        if self == response:
            calls.append(1)
        return read(self)

    monkeypatch.setattr(Path, "read_bytes", counted)
    prep.prepare_compile_commands(path, [])
    assert len(calls) == 1  # Separate commit validation still rehashes each input.


@pytest.fixture(params=["clang", "batch"])
def real_checker(request):
    kind = request.param
    command = (
        os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER") if kind == "batch" else shutil.which("clang")
    )
    if not command:
        pytest.skip("real argument checker unavailable")
    if kind == "batch":
        capability = json.loads(subprocess.check_output([command, "--version"], text=True))
        if not capability.get("argument_check_protocol"):
            pytest.skip("native argument checker needs rebuild")
    return CheckTool(kind, command, kind, executable_identity(command))


def test_real_preflight_no_tu_parse_and_warm_no_process(tmp_path, real_checker, monkeypatch):
    path = database(
        tmp_path, ["-m32", "-Werror", "-Wunknown-zscope-warning", "-Xclang", "-funknown-zscope"]
    )
    source = tmp_path / "tu0.c"
    source.write_text("#error unknown argument: '-DKEEP'\n#include \"missing.h\"\n")
    receipt = prep.prepare_compile_commands(path, [real_checker], host_arch="x86_64")
    effective = json.loads(path.read_text())[0]["arguments"]
    assert "-m32" not in effective and "-m64" in effective
    assert "-Wunknown-zscope-warning" not in effective and "-funknown-zscope" not in effective
    report = json.loads(Path(receipt.report_path).read_text())
    assert report["stats"]["unverified"] == 0
    assert not (tmp_path / "tu0.o").exists()
    monkeypatch.setattr(
        prep, "preflight", lambda *a: pytest.fail("hot preparation starts argument checker")
    )
    prep.prepare_compile_commands(path, [real_checker], host_arch="x86_64")
    compiler = shutil.which("clang")
    assert compiler
    actual = subprocess.run([compiler, *effective[1:]], capture_output=True, text=True)
    assert actual.returncode != 0 and "missing.h" in actual.stderr


def test_real_preflight_keeps_invalid_value(real_checker, tmp_path):
    args, _ = probe_arguments(["clang", "-std=invalid-zscope", "-c", "tu.c"], "tu.c", tmp_path)
    result = preflight(real_checker, args, tmp_path, os.environ.copy())
    assert result["status"] == "unverified" and result["removed_unknown_options"] == []


@pytest.mark.parametrize(
    "options,remaining",
    [
        (["-m64", "-Xclang", "-m64"], ["-m64"]),
        (["-verify", "-Xclang", "-verify"], ["-Xclang", "-verify"]),
        (["-funknown-driver-zscope", "-Xclang", "-funknown-frontend-zscope"], []),
    ],
)
def test_unknown_scopes_do_not_delete_valid_other_stream(
    real_checker, tmp_path, options, remaining
):
    path = database(tmp_path, options)
    receipt = prep.prepare_compile_commands(path, [real_checker])
    effective = json.loads(path.read_text())[0]["arguments"]
    assert effective[1 : 1 + len(remaining)] == remaining
    assert effective[1 + len(remaining)] == "-c"
    report = json.loads(Path(receipt.report_path).read_text())
    assert report["stats"]["unverified"] == 0


def test_forwarded_linker_assembler_operands_are_untouched():
    args = [
        "clang",
        "-Wl,--script,--fatal-warnings,--fatal-warnings,-z,now",
        "-Wa,--defsym,--fatal-warnings,--fatal-warnings",
    ]
    assert adjust_arguments(args)[0] == [
        "clang",
        "-Wl,--script,--fatal-warnings,-z,now",
        "-Wa,--defsym,--fatal-warnings",
    ]


def test_interrupt_after_database_commit_recovers_original_backup(tmp_path, monkeypatch):
    path = database(tmp_path, ["-m32", "-Werror"])
    raw = path.read_bytes()
    write = prep._write

    def crash(target, data, **kwargs):
        write(target, data, **kwargs)
        if target == path:
            raise KeyboardInterrupt()

    monkeypatch.setattr(prep, "_write", crash)
    with pytest.raises(KeyboardInterrupt):
        prep.prepare_compile_commands(path, [], host_arch="x86_64")
    monkeypatch.setattr(prep, "_write", write)
    receipt = prep.prepare_compile_commands(path, [], host_arch="x86_64")
    assert receipt.original_digest == prep._bytes_digest(raw)
    receipt.validate()


def test_preparation_receipt_detects_response_symlink_retarget(tmp_path):
    (tmp_path / "one.rsp").write_text("-Werror")
    (tmp_path / "two.rsp").write_text("-Werror")
    response = tmp_path / "linked.rsp"
    response.symlink_to("one.rsp")
    path = database(tmp_path, ["@linked.rsp"])
    receipt = prep.prepare_compile_commands(path, [])
    response.unlink()
    response.symlink_to("two.rsp")
    with pytest.raises(RuntimeError, match="changed"):
        receipt.validate()


def test_preflight_timeout_has_no_persistent_delete_authority(tmp_path, monkeypatch):
    from zscope.retrieval import compile_preflight as probe

    calls = []

    def check(tool, arguments, directory, deadline, env):
        calls.append(deadline)
        if len(calls) == 1:
            return dict(status="unknown", unknown=["-funknown"], unknown_scopes={"-funknown": [""]})
        raise subprocess.TimeoutExpired(arguments, 10)

    monkeypatch.setattr(probe, "check_once", check)
    result = preflight(CheckTool("clang", "clang"), ["clang", "-funknown"], tmp_path, {})
    assert calls[0] == calls[1] and len(result["attempts"]) == 2
    assert result["status"] == "unverified" and result["removed_unknown_options"] == []


def test_mj_output_never_created_by_preflight(real_checker, tmp_path):
    out = tmp_path / "should-not-exist.json"
    path = database(tmp_path, ["-MJ" + str(out)])
    prep.prepare_compile_commands(path, [real_checker])
    assert not out.exists()


def test_native_argument_api_suppresses_driver_outputs(tmp_path):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native checker required")
    source, output = tmp_path / "source.c", tmp_path / "fragment.json"
    source.write_text("#error must not parse the source\n")
    job = tmp_path / "job.json"
    job.write_text(json.dumps(dict(arguments=["clang", "-c", str(source), "-MJ", str(output)])))
    response = json.loads(
        subprocess.check_output(
            [executable, "--check-arguments", str(job)], text=True, cwd=tmp_path
        )
    )
    assert response["errors"] == 0 and response["targets"]
    assert not output.exists() and not (tmp_path / "source.o").exists()
    assert all("\x00" not in diagnostic["message"] for diagnostic in response["diagnostics"])


@pytest.mark.parametrize("wrapper", [False, True])
def test_standalone_bitcode_uses_prepared_database_before_tasks(tmp_path, monkeypatch, wrapper):
    from zscope.retrieval.build_llvm import BitcodeBuilder
    from zscope.retrieval.llvm_toolchain import matching_clang

    link = shutil.which("llvm-link")
    gclang, get_bc = shutil.which("gclang"), shutil.which("get-bc")
    if not link or not matching_clang(link) or (wrapper and not (gclang and get_bc)):
        pytest.skip("matching LLVM/gllvm toolchain required")
    path = database(tmp_path, ["-m32", "-Werror", "-Xclang", "-funknown-zscope"])
    rows = json.loads(path.read_text())
    if wrapper:
        rows[0]["arguments"].insert(0, "ccache")
        path.write_text(json.dumps(rows))
    (tmp_path / "tu0.c").write_text("#warning allowed\nint main(void) { return 0; }\n")
    monkeypatch.setenv("Z_SCOPE_BITCODE_MEMORY_MB", "256")
    builder = BitcodeBuilder(
        tmp_path,
        path,
        output_dir=tmp_path / "bc",
        llvm_link_path=link,
        gclang_path=gclang or "gclang",
        get_bc_path=get_bc or "get-bc",
    )
    assert builder.build() and not builder.failed_tus
    attempts = list(builder._manifest["attempts"].values())
    assert len(attempts) == 1 and attempts[0]["status"] == "compiled"
    assert len(attempts[0]["argument_adjustments"]["attempts"]) == 1
    assert attempts[0]["argument_adjustments"]["removed_unknown_options"] == []
    assert "-m32" not in path.read_text() and "-m64" in path.read_text()
    assert builder.build()
    assert next(iter(builder._manifest["attempts"].values()))["status"] == "reused"


@pytest.mark.parametrize("rewrite_after_compile", [False, True])
def test_bitcode_source_version_is_independent_of_wall_clock(
    tmp_path, monkeypatch, rewrite_after_compile
):
    from zscope.retrieval import bitcode_compile
    from zscope.retrieval.build_llvm import BitcodeBuilder
    from zscope.retrieval.llvm_toolchain import matching_clang

    link = shutil.which("llvm-link")
    if not link or not matching_clang(link):
        pytest.skip("matching LLVM toolchain required")
    path = database(tmp_path, [])
    source = tmp_path / "tu0.c"
    code = "int main(void) { return 0; }\n"
    source.write_text(code)
    os.utime(source, ns=(source.stat().st_atime_ns, time.time_ns() + 5_000_000_000))
    original = bitcode_compile.run_process

    def run(*args, **kwargs):
        result = original(*args, **kwargs)
        if rewrite_after_compile and kwargs.get("label", "").startswith("bitcode-compile:"):
            before = source.stat()
            source.write_text(code)
            os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        return result

    monkeypatch.setattr(bitcode_compile, "run_process", run)
    monkeypatch.setenv("Z_SCOPE_BITCODE_MEMORY_MB", "256")
    builder = BitcodeBuilder(tmp_path, path, output_dir=tmp_path / "bc", llvm_link_path=link)
    output = builder.build()
    if rewrite_after_compile:
        assert output == {}
        assert builder.failed_tus[0]["reason"] == "dependency_changed_during_compile"
    else:
        assert output and not builder.failed_tus


def test_unified_deferred_svf_keeps_same_preparation_receipt(tmp_path, monkeypatch):
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.unified_backend import UnifiedBackend
    from zscope.retrieval.svf_analyzer import SvfAnalyzer

    path = database(tmp_path, ["-Werror"])
    receipt = prep.prepare_compile_commands(path, [])

    def initialize(self, source_path, **kwargs):
        assert kwargs["compile_preparation_tools"] == {
            "llvm_link": "paired-link",
            "gclang": "paired-gclang",
        }
        from zscope.retrieval.knowledge_db import KnowledgeDB

        self._db = KnowledgeDB(str(tmp_path / "knowledge.db"))
        self._compile_preparation = receipt
        return True

    observed = []

    def run(self, *args, **kwargs):
        assert self._compile_preparation is receipt
        receipt.validate()
        observed.append(receipt.effective_digest)
        return True

    monkeypatch.setattr(ClangBackend, "initialize", initialize)
    monkeypatch.setattr(UnifiedBackend, "_check_svf_tools", lambda self: [])
    monkeypatch.setattr(SvfAnalyzer, "run", run)
    backend = UnifiedBackend(llvm_link_path="paired-link", gclang_path="paired-gclang")
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(path), defer_svf=True)
        assert not observed
        monkeypatch.setattr(
            prep,
            "prepare_compile_commands",
            lambda *a, **kw: pytest.fail("deferred SVF rewrites CDB"),
        )
        assert backend.run_svf() and observed == [receipt.effective_digest]
    finally:
        backend.close()
