"""Automatic replay must not inherit source migration or side-output actions."""

import pytest

from zscope.core.validation.dynamic_reproduction import DynamicReproductionError
from zscope.core.validation.reproduction_planner import SessionReproductionPlanner


@pytest.mark.parametrize(
    "flag",
    [
        "-objcmt-migrate-all",
        "-objcmt-migrate-literals",
        "-fsave-optimization-record",
        "-foptimization-record-file=source.opt.yaml",
        "-fmodule-output=source.pcm",
    ],
)
def test_automatic_build_rejects_migration_and_unmanaged_side_outputs(tmp_path, flag):
    with pytest.raises(DynamicReproductionError, match="unsupported_build_mode"):
        SessionReproductionPlanner._build_arguments(
            ["clang", "-c", "unit.c", flag], {}, "/usr/bin/clang", tmp_path / "program", "asan"
        )


def test_language_selection_and_debug_identity_survive_output_redirection(tmp_path):
    args = SessionReproductionPlanner._build_arguments(
        ["clang", "-c", "unit.m", "-ObjC", "-object-file-name=original.o", "-o", "unit.o"],
        {},
        "/usr/bin/clang",
        tmp_path / "program",
        "asan",
    )
    assert "-ObjC" in args and "-object-file-name=original.o" in args
    assert "unit.o" not in args
    assert args[-2:] == ["-o", str(tmp_path / "program")]
