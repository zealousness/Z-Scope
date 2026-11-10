import pytest

from zscope.retrieval.svf_runner import SvfRunner


@pytest.mark.parametrize("tool", ["wpa", "saber"])
def test_explicit_missing_svf_directory_does_not_use_path(tmp_path, monkeypatch, tool):
    fallback = tmp_path / "fallback"
    fallback.mkdir()
    marker = tmp_path / "unexpected-tool"
    executable = fallback / tool
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(fallback) + ":/usr/bin:/bin")
    runner = SvfRunner(svf_bin_dir=str(tmp_path / "missing"), timeout=10)
    method = runner.run_ander if tool == "wpa" else runner.run_saber
    result = method(tmp_path / "input.bc", tmp_path / "output")
    assert not result.success
    assert "binary not found" in result.stderr
    assert not marker.exists()


def test_relative_svf_directory_retains_caller_base_and_precedes_path(tmp_path, monkeypatch):
    directory = tmp_path / "sdk" / "bin"
    directory.mkdir(parents=True)
    executable = directory / "wpa"
    executable.write_text("#!/bin/sh\nprintf 'digraph G {}\\n' > callgraph_final.dot\n")
    executable.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    runner = SvfRunner(svf_bin_dir="sdk/bin", timeout=10)
    result = runner.run_ander(tmp_path / "input.bc", tmp_path / "separate working directory")
    assert result.success
    assert result.output_file and result.output_file.read_text() == "digraph G {}\n"
