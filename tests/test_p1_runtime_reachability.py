from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

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


def test_successor_review_governance_projectors_have_exact_source_exemptions(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "zscope" / "orchestration"
    source_root.mkdir(parents=True)
    for name in ("successor_review_evidence", "successor_review_integration"):
        (source_root / f"{name}.py").write_text(
            "from zscope.benchmarking.p6_protocol import canonical_sha256\n",
            encoding="utf-8",
        )

    assert source_import_errors(tmp_path) == []


def test_successor_runtime_review_status_remains_live_denied_in_source(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "zscope" / "orchestration"
    source_root.mkdir(parents=True)
    (source_root / "successor_runtime_review_status.py").write_text(
        "from zscope.benchmarking.p6_protocol import P6ProtocolError\n",
        encoding="utf-8",
    )

    assert source_import_errors(tmp_path) == [
        "zscope/orchestration/successor_runtime_review_status: "
        "live runtime imports isolated package zscope.benchmarking.p6_protocol"
    ]


@pytest.mark.parametrize(
    ("source", "projector"),
    (
        (
            "import zscope.orchestration.successor_review_evidence\n",
            "zscope.orchestration.successor_review_evidence",
        ),
        (
            "from zscope.orchestration import successor_review_integration\n",
            "zscope.orchestration.successor_review_integration",
        ),
        (
            "from . import successor_review_evidence\n",
            "zscope.orchestration.successor_review_evidence",
        ),
        (
            "from .successor_review_integration import validate_receipt\n",
            "zscope.orchestration.successor_review_integration",
        ),
        (
            "import importlib\n"
            "importlib.import_module('zscope.orchestration.successor_review_evidence')\n",
            "zscope.orchestration.successor_review_evidence",
        ),
        (
            "from importlib import import_module as load_module\n"
            "load_module('zscope.orchestration.successor_review_integration')\n",
            "zscope.orchestration.successor_review_integration",
        ),
        (
            "__import__('zscope.orchestration.successor_review_evidence')\n",
            "zscope.orchestration.successor_review_evidence",
        ),
    ),
)
def test_live_source_cannot_import_governance_projectors(
    tmp_path: Path,
    source: str,
    projector: str,
) -> None:
    source_root = tmp_path / "zscope" / "orchestration"
    source_root.mkdir(parents=True)
    (source_root / "runtime.py").write_text(source, encoding="utf-8")

    assert source_import_errors(tmp_path) == [
        f"zscope/orchestration/runtime: imports governance-only projector {projector}"
    ]


def test_wheel_gate_accepts_p1_package_shape(tmp_path: Path) -> None:
    wheel = tmp_path / "zscope-p1.whl"
    _write_wheel(wheel)

    assert wheel_errors(wheel) == []


def test_successor_review_governance_projectors_have_exact_wheel_exemptions(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "zscope-p1-governance.whl"
    _write_wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        for name in ("successor_review_evidence", "successor_review_integration"):
            archive.writestr(
                f"zscope/orchestration/{name}.py",
                "from zscope.benchmarking.p6_protocol import canonical_sha256\n",
            )

    assert wheel_errors(wheel) == []


def test_successor_runtime_review_status_remains_live_denied_in_wheel(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "zscope-p1-status-bypass.whl"
    _write_wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(
            "zscope/orchestration/successor_runtime_review_status.py",
            "from zscope.benchmarking.p6_protocol import P6ProtocolError\n",
        )

    assert wheel_errors(wheel) == [
        "zscope/orchestration/successor_runtime_review_status.py: "
        "live runtime imports isolated package zscope.benchmarking.p6_protocol"
    ]


@pytest.mark.parametrize(
    ("source", "projector"),
    (
        (
            "import zscope.orchestration.successor_review_evidence\n",
            "zscope.orchestration.successor_review_evidence",
        ),
        (
            "from zscope.orchestration import successor_review_integration\n",
            "zscope.orchestration.successor_review_integration",
        ),
        (
            "from . import successor_review_evidence\n",
            "zscope.orchestration.successor_review_evidence",
        ),
        (
            "from .successor_review_integration import validate_receipt\n",
            "zscope.orchestration.successor_review_integration",
        ),
        (
            "import importlib as loader\n"
            "loader.import_module('zscope.orchestration.successor_review_evidence')\n",
            "zscope.orchestration.successor_review_evidence",
        ),
        (
            "from importlib import import_module\n"
            "import_module('zscope.orchestration.successor_review_integration')\n",
            "zscope.orchestration.successor_review_integration",
        ),
        (
            "__import__('zscope.orchestration.successor_review_evidence')\n",
            "zscope.orchestration.successor_review_evidence",
        ),
    ),
)
def test_live_wheel_module_cannot_import_governance_projectors(
    tmp_path: Path,
    source: str,
    projector: str,
) -> None:
    wheel = tmp_path / "zscope-p1-projector-bypass.whl"
    _write_wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("zscope/orchestration/runtime.py", source)

    assert wheel_errors(wheel) == [
        "zscope/orchestration/runtime.py: imports governance-only projector " f"{projector}"
    ]


def test_wheel_gate_rejects_removed_agent(tmp_path: Path) -> None:
    wheel = tmp_path / "zscope-p1.whl"
    _write_wheel(wheel, include_removed=True)

    assert any("deep_worker" in error for error in wheel_errors(wheel))


def test_wheel_gate_rejects_live_compat_import(tmp_path: Path) -> None:
    wheel = tmp_path / "zscope-p5-compat-bypass.whl"
    _write_wheel(wheel, include_live_compat_import=True)

    assert any("zscope.compat" in error for error in wheel_errors(wheel))
