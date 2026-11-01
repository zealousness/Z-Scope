from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from zscope.common.portable import default_tool, java_jar
from zscope.config.config import ConfigLoader
from zscope.retrieval.java_source_backend import JavaSourceBackend
from zscope.retrieval.svf_runner import SvfRunner


def bundle(tmp_path, monkeypatch, profile="cpp"):
    root = tmp_path / "portable with spaces"
    (root / "bin").mkdir(parents=True)
    launcher = root / "bin/zscope-launch"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    names = (
        ("clangd", "zscope-clang-indexer", "wpa", "saber", "gclang", "get-bc", "llvm-link")
        if profile == "cpp"
        else ("java", "joern", "mvn")
    )
    for name in names:
        (root / "bin" / name).symlink_to("zscope-launch")
    manifest = {
        "schema_version": "zscope.portable.v1",
        "profile": profile,
        "arch": "x86_64",
        "tools": {name: "bin/" + name for name in names},
        "java_jars": {},
    }
    (root / "bundle.json").write_text(json.dumps(manifest))
    monkeypatch.setenv("Z_SCOPE_BUNDLE_ROOT", str(root))
    return root, manifest


def config_file(tmp_path, tools=None):
    path = tmp_path / "config.yaml"
    data = {
        "config_version": 2,
        "llms": {
            "default": {"base_urls": ["http://localhost/v1"], "models": ["unit"], "api_key": "unit"}
        },
        "project": {"language": "c_cpp"},
        "indexing": {"backend": "unified"},
    }
    if tools is not None:
        data["indexing"]["tools"] = tools
    data["concurrency"] = {
        key: 1
        for key in (
            "entry_workers",
            "validator_workers",
            "investigator_workers",
            "evidence_completion_workers",
            "index_workers",
            "llm_max_inflight",
            "svf_workers",
        )
    }
    path.write_text(json.dumps(data))
    return path


def test_bundled_command_retains_dispatch_symlink_name(tmp_path, monkeypatch):
    root, _ = bundle(tmp_path, monkeypatch)
    assert default_tool("clangd") == str(root / "bin/clangd")
    assert default_tool("clangd") != str(root / "bin/zscope-launch")
    assert ConfigLoader.load(str(config_file(tmp_path))).indexing.clangd_path == str(
        root / "bin/clangd"
    )
    assert ConfigLoader.load(str(config_file(tmp_path))).indexing.clang_indexer_path == str(
        root / "bin/zscope-clang-indexer"
    )


def test_explicit_configuration_survives_bundle_defaults_and_is_not_rewritten(
    tmp_path, monkeypatch
):
    bundle(tmp_path, monkeypatch)
    path = config_file(
        tmp_path,
        {
            "clangd": "/experimental/missing-clangd",
            "svf_bin_dir": "/experimental/svf",
            "clang_indexer": "/experimental/missing-indexer",
        },
    )
    original = path.read_bytes()
    configured = ConfigLoader.load(str(path))
    assert configured.indexing.clangd_path == "/experimental/missing-clangd"
    assert configured.indexing.svf_bin_dir == "/experimental/svf"
    assert configured.indexing.clang_indexer_path == "/experimental/missing-indexer"
    assert path.read_bytes() == original
    runner = SvfRunner(svf_bin_dir=configured.indexing.svf_bin_dir)
    assert runner._tool_path("wpa") == "/experimental/svf/wpa"


def test_missing_or_escaping_bundled_resources_never_fall_back(tmp_path, monkeypatch):
    root, manifest = bundle(tmp_path, monkeypatch)
    with pytest.raises(FileNotFoundError, match="does not contain"):
        default_tool("java")
    (root / "bin/clangd").unlink()
    with pytest.raises(FileNotFoundError):
        default_tool("clangd")
    manifest["tools"]["clangd"] = "../../outside"
    (root / "bundle.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="escapes"):
        default_tool("clangd")


def test_make_dispatch_uses_path_name_for_recursive_recipes(tmp_path, monkeypatch):
    import os
    import runpy
    import sys

    root, manifest = bundle(tmp_path, monkeypatch)
    manifest["executables"] = {"make": "tools/build/bin/make"}
    (root / "bundle.json").write_text(json.dumps(manifest))
    captured = []

    class Executed(Exception):
        pass

    def execute(path, arguments):
        captured.append((path, arguments))
        raise Executed

    monkeypatch.setattr(os, "execv", execute)
    monkeypatch.setattr(sys, "argv", ["dispatch.py", "make", "-f", "Makefile"])
    with pytest.raises(Executed):
        runpy.run_path(str(Path(__file__).parents[1] / "scripts/portable/dispatch.py"))
    assert captured == [(str(root / "tools/build/bin/make"), ["make", "-f", "Makefile"])]


def test_source_install_keeps_path_discovery(monkeypatch):
    monkeypatch.delenv("Z_SCOPE_BUNDLE_ROOT", raising=False)
    assert default_tool("clangd") == "clangd"
    assert java_jar("structure-spoon") is None


@pytest.mark.skipif(os.name != "posix", reason="ELF loader paths are Linux-only")
def test_path_selected_svf_uses_libraries_from_the_same_install(tmp_path, monkeypatch):
    from zscope.retrieval.llvm_toolchain import svf_environment

    prefix = tmp_path / "selected"
    foreign = tmp_path / "foreign"
    svf_bin = prefix / "svf/bin"
    svf_lib = prefix / "svf/lib"
    llvm_lib = prefix / "llvm18/lib"
    for directory in (svf_bin, svf_lib, llvm_lib, foreign):
        directory.mkdir(parents=True)
    wpa = svf_bin / "wpa"
    wpa.write_text("#!/bin/sh\nexit 0\n")
    wpa.chmod(0o755)
    monkeypatch.delenv("Z_SCOPE_BUNDLE_ROOT", raising=False)
    monkeypatch.setenv("PATH", str(svf_bin))
    monkeypatch.setenv("LD_LIBRARY_PATH", str(foreign))

    environment = svf_environment("")

    search = environment["LD_LIBRARY_PATH"].split(os.pathsep)
    assert search[:2] == [str(svf_lib.resolve()), str(llvm_lib.resolve())]
    assert search[-1] == str(foreign)


def test_compiler_selection_keeps_launcher_name_and_svf_checks_its_elf(tmp_path, monkeypatch):
    from subprocess import CompletedProcess
    from zscope.common.portable import bundled_executable
    from zscope.retrieval import llvm_toolchain

    root, manifest = bundle(tmp_path, monkeypatch)
    manifest["executables"] = {}
    for name in ("wpa", "saber", "clang++"):
        target = root / "tools/native/bin" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"real executable")
        target.chmod(0o755)
        manifest["executables"][name] = target.relative_to(root).as_posix()
    (root / "bin/clang++").symlink_to("zscope-launch")
    (root / "bundle.json").write_text(json.dumps(manifest))
    monkeypatch.setenv("PATH", str(root / "bin"))
    monkeypatch.setenv("LLVM_CXX_NAME", str(root / "bin/clang++"))
    monkeypatch.delenv("LLVM_COMPILER_PATH", raising=False)
    monkeypatch.setattr(llvm_toolchain, "tool_major", lambda *args: 18)
    observed = []

    def ldd(args, **kwargs):
        observed.append(args)
        return CompletedProcess(
            args,
            0,
            stdout="libLLVM.so.18.1 => /bundle with spaces/lib/libLLVM.so.18.1 (0x1)\n",
            stderr="",
        )

    monkeypatch.setattr(llvm_toolchain.subprocess, "run", ldd)
    assert llvm_toolchain.matching_clang("llvm-link", cxx=True) == str(root / "bin/clang++")
    llvm_toolchain.validate_svf_llvm(str(root / "bin"), "llvm-link")
    assert all(Path(args[1]).parent == root / "tools/native/bin" for args in observed)
    external_alias = tmp_path / "external alias"
    external_alias.symlink_to(root / "bin/wpa")
    assert bundled_executable(str(external_alias)) == root / "tools/native/bin/wpa"


def test_java_explicit_command_has_no_builtin_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("Z_SCOPE_BUNDLE_ROOT", raising=False)
    backend = JavaSourceBackend(frontend="javaparser", extractor_command=["/missing/experiment"])
    assert backend._frontend_plan() == ["javaparser"]
    (tmp_path / "Example.java").write_text("class Example { int answer() { return 42; } }")
    assert backend.initialize(str(tmp_path), project_root=tmp_path) is False


def test_portable_java_requires_prebuilt_jars_without_invoking_maven(tmp_path, monkeypatch):
    bundle(tmp_path, monkeypatch, "java")
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: pytest.fail("build/download attempted"))
    with pytest.raises(FileNotFoundError):
        JavaSourceBackend()._ensure_default_javaparser_jar()


@pytest.mark.parametrize("filename", ["zscope.c_cpp.yaml", "zscope.java.yaml"])
def test_language_templates_hide_tool_configuration_and_examples(filename):
    source = (Path(__file__).parents[1] / filename).read_text(encoding="utf-8")
    parsed = yaml.safe_load(source)
    from zscope.config.v3 import V3_TOP_LEVEL_KEYS

    assert parsed["config_version"] == 3
    assert set(parsed) <= set(V3_TOP_LEVEL_KEYS)
    assert {"llms", "project", "scan"} <= set(parsed)
    assert "indexing" not in parsed and "tools" not in parsed
    for text in (
        "extractor_command",
        "provider_commands",
        "svf_bin_dir",
        "clangd_path",
        "java -jar",
        "/path/to/joern",
    ):
        assert text not in source
