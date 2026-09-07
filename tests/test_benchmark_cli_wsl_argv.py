"""Tests for the zscope-benchmark CLI helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

from zscope.cli.benchmark import _wsl_argv


def test_wsl_argv_converts_root_and_output_paths_to_posix():
    """wsl.exe strips backslashes from bare argv, so paths must go through
    wslpath as forward-slash Windows paths (regression: ``C:\\Users`` arrived
    in WSL as ``C:Users`` and wslpath exited 1)."""

    def fake_check_output(argv, **kwargs):
        if argv[:2] == ["wsl", "wslpath"]:
            windows_path = argv[3]
            assert "\\" not in windows_path, windows_path
            mapping = {
                str(Path(__file__).resolve().parent.parent).replace("\\", "/"): "/mnt/c/repo\n",
                "C:/tmp/out": "/mnt/c/tmp/out\n",
            }
            return mapping[windows_path]
        raise AssertionError(f"unexpected argv: {argv}")

    with mock.patch.object(subprocess, "check_output", side_effect=fake_check_output):
        argv = _wsl_argv(
            ["run", "--language", "c_cpp", "--mode", "trial", "--output", r"C:\tmp\out"]
        )

    assert argv[0] == "wsl"
    assert "cd /mnt/c/repo" in argv[-1]
    assert "/mnt/c/tmp/out" in argv[-1]
