from __future__ import annotations

import zipfile
from pathlib import Path

from scripts.check_p1_runtime_reachability import (
    REQUIRED_WHEEL_ENTRIES,
    source_import_errors,
    wheel_errors,
)


ROOT = Path(__file__).resolve().parents[1]


def _write_wheel(
    path: Path, *, include_removed: bool = False, include_live_compat_import: bool = False
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in REQUIRED_WHEEL_ENTRIES:
            archive.writestr(name, "# packaged P1 entry\n")
        archive.writestr(
            "zscope/runtime.py",
            (
                "from zscope.compat import read_legacy_report_view\n"
                if include_live_compat_import
                else "RUNTIME_AUTHORITY = 'p5'\n"
            ),
        )
        if include_removed:
            archive.writestr("zscope/agents/deep_worker/agent.py", "# removed\n")


def test_repository_import_graph_excludes_removed_runtime_and_compat_is_read_only() -> None:
    assert source_import_errors(ROOT) == []


def test_wheel_gate_accepts_p1_package_shape(tmp_path: Path) -> None:
    wheel = tmp_path / "zscope-p1.whl"
    _write_wheel(wheel)

    assert wheel_errors(wheel) == []


def test_wheel_gate_rejects_removed_agent(tmp_path: Path) -> None:
    wheel = tmp_path / "zscope-p1.whl"
    _write_wheel(wheel, include_removed=True)

    assert any("deep_worker" in error for error in wheel_errors(wheel))


def test_wheel_gate_rejects_live_compat_import(tmp_path: Path) -> None:
    wheel = tmp_path / "zscope-p5-compat-bypass.whl"
    _write_wheel(wheel, include_live_compat_import=True)

    assert any("zscope.compat" in error for error in wheel_errors(wheel))
