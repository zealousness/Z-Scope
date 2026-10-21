"""SVF wpa memory-budget pre-check tests (P0-M2)."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def deterministic_memory_budget(monkeypatch):
    monkeypatch.setattr(
        "zscope.retrieval.indexing_runtime.resource_limits",
        lambda: {"cpu_count": 16, "task_memory_budget_bytes": 128 * 1024**3},
    )


from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.retrieval.svf_analyzer import SvfAnalyzer
from zscope.retrieval.svf_runner import SvfResult


class FakeWpaRunner:
    """Records wpa invocations without running a subprocess."""

    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.calls: list[str] = []

    def run_ander(self, bc_path: Path, output_dir: Path) -> SvfResult:
        self.calls.append(str(bc_path))
        output_dir.mkdir(parents=True, exist_ok=True)
        dot = output_dir / "callgraph_final.dot"
        dot.write_text("digraph { }\n", encoding="utf-8")
        return SvfResult(
            tool="wpa-ander",
            success=self.succeed,
            output_file=dot,
        )


def make_analyzer(tmp_path: Path, *, heap_limit_mb: int) -> SvfAnalyzer:
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    analyzer = SvfAnalyzer(db=db, heap_limit_mb=heap_limit_mb, parallel_workers=1)
    analyzer._project_root = tmp_path
    return analyzer


def make_bc(tmp_path: Path, *, size_mb: float) -> Path:
    bc = tmp_path / "merged_default.bc"
    bc.write_bytes(b"0" * int(size_mb * 1024 * 1024))
    return bc


def test_budget_not_exceeded_for_small_bc(tmp_path: Path) -> None:
    analyzer = make_analyzer(tmp_path, heap_limit_mb=8192)
    bc = make_bc(tmp_path, size_mb=1)
    assert analyzer._wpa_memory_budget_exceeded(bc) is False


def test_budget_exceeded_for_small_heap(tmp_path: Path) -> None:
    analyzer = make_analyzer(tmp_path, heap_limit_mb=8)
    bc = make_bc(tmp_path, size_mb=1)
    # default factor 25 -> estimate 25 MB > 8 MB heap
    assert analyzer._wpa_memory_budget_exceeded(bc) is True


def test_env_factor_overrides_default(tmp_path: Path, monkeypatch) -> None:
    analyzer = make_analyzer(tmp_path, heap_limit_mb=8)
    bc = make_bc(tmp_path, size_mb=1)

    monkeypatch.setenv("Z_SCOPE_SVF_BC_MEMORY_FACTOR", "0")
    assert analyzer._wpa_memory_budget_exceeded(bc) is False

    monkeypatch.setenv("Z_SCOPE_SVF_BC_MEMORY_FACTOR", "not-a-number")
    assert analyzer._wpa_memory_budget_exceeded(bc) is True


def test_wpa_group_skipped_when_over_budget(tmp_path: Path) -> None:
    analyzer = make_analyzer(tmp_path, heap_limit_mb=8)
    bc = make_bc(tmp_path, size_mb=1)
    runner = FakeWpaRunner()

    had_timeout = analyzer._run_wpa_groups(runner, {"default": bc}, tmp_path)

    assert had_timeout is True
    assert runner.calls == []
    status = analyzer._load_tool_status("ander", "default")
    assert status.get("status") == "skipped_memory_budget"
    assert status.get("timed_out") is False


def test_wpa_group_runs_when_within_budget(tmp_path: Path) -> None:
    analyzer = make_analyzer(tmp_path, heap_limit_mb=32768)
    bc = make_bc(tmp_path, size_mb=1)
    runner = FakeWpaRunner()

    had_timeout = analyzer._run_wpa_groups(runner, {"default": bc}, tmp_path)

    assert had_timeout is False
    assert len(runner.calls) == 1
    status = analyzer._load_tool_status("ander", "default")
    assert status.get("status") == "success"


def test_missing_bc_file_is_not_budget_blocked(tmp_path: Path) -> None:
    analyzer = make_analyzer(tmp_path, heap_limit_mb=8)
    bc = tmp_path / "missing.bc"
    assert analyzer._wpa_memory_budget_exceeded(bc) is False
