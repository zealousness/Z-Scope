"""Parallel saber group execution tests (P0-M1)."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Dict, List

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


class FakeSaberRunner:
    """Records concurrency and per-group results without running a subprocess."""

    def __init__(self, results: Dict[str, bool], *, barrier_ms: int = 0):
        self.results = results
        self.barrier_ms = barrier_ms
        self.calls: List[str] = []
        self.calls_lock = threading.Lock()
        self.active = 0
        self.peak_active = 0
        self.active_lock = threading.Lock()

    def run_saber(self, bc_path: Path, output_dir: Path) -> SvfResult:
        stem = Path(bc_path).stem
        prefix = "merged_"
        group_name = "saber:" + stem[len(prefix) :] if stem.startswith(prefix) else stem
        with self.calls_lock:
            self.calls.append(group_name)
        with self.active_lock:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
        try:
            if self.barrier_ms:
                # Give the executor a chance to overlap every group.
                time.sleep(self.barrier_ms / 1000.0)
            result = SvfResult(tool="saber")
            result.success = bool(self.results.get(group_name, True))
            result.bugs = [{"type": "Memory Leak", "file": "a.c", "line": 10}]
            return result
        finally:
            with self.active_lock:
                self.active -= 1


def make_analyzer(
    tmp_path: Path,
    *,
    parallel_workers: int,
    heap_limit_mb: int = 32768,
) -> SvfAnalyzer:
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    analyzer = SvfAnalyzer(
        db=db,
        parallel_workers=parallel_workers,
        heap_limit_mb=heap_limit_mb,
    )
    analyzer._project_root = tmp_path
    return analyzer


def make_paths(tmp_path: Path, group_names: List[str]) -> Dict[str, Path]:
    paths: Dict[str, Path] = {}
    for name in group_names:
        bc = tmp_path / f"merged_{name}.bc"
        bc.write_bytes(("fake-bitcode:" + name).encode())
        paths[f"saber:{name}"] = bc
    return paths


def test_saber_worker_count_bounds(tmp_path: Path) -> None:
    analyzer = make_analyzer(tmp_path, parallel_workers=8)
    # Reserve 32 GiB per process from the simulated 128 GiB task budget.
    assert analyzer._saber_worker_count(10) == 4
    assert analyzer._saber_worker_count(2) == 2
    assert analyzer._saber_worker_count(0) == 0

    small_heap = make_analyzer(tmp_path, parallel_workers=8, heap_limit_mb=8192)
    assert small_heap._saber_worker_count(10) == 8

    few_workers = make_analyzer(tmp_path, parallel_workers=2)
    assert few_workers._saber_worker_count(10) == 2


def test_saber_groups_run_in_parallel(tmp_path: Path) -> None:
    groups = [f"g{i}" for i in range(4)]
    saber_paths = make_paths(tmp_path, groups)
    runner = FakeSaberRunner({}, barrier_ms=250)
    analyzer = make_analyzer(tmp_path, parallel_workers=4)

    had_failure = analyzer._run_saber_groups(runner, saber_paths, tmp_path)

    assert had_failure is False
    assert sorted(runner.calls) == sorted(f"saber:{name}" for name in groups)
    assert runner.peak_active >= 2, "groups should overlap across workers"
    for name in groups:
        status = analyzer._load_tool_status("saber", f"saber:{name}")
        assert status.get("status") == "success"


def test_saber_groups_report_failures(tmp_path: Path) -> None:
    groups = ["ok1", "bad1", "ok2"]
    saber_paths = make_paths(tmp_path, groups)
    runner = FakeSaberRunner({"saber:bad1": False}, barrier_ms=50)
    analyzer = make_analyzer(tmp_path, parallel_workers=3)

    had_failure = analyzer._run_saber_groups(runner, saber_paths, tmp_path)

    assert had_failure is True
    assert analyzer._load_tool_status("saber", "saber:bad1").get("status") == "failed"
    assert analyzer._load_tool_status("saber", "saber:ok1").get("status") == "success"


def test_saber_groups_skip_cached_groups(tmp_path: Path) -> None:
    groups = ["cached", "fresh"]
    saber_paths = make_paths(tmp_path, groups)
    runner = FakeSaberRunner({}, barrier_ms=10)
    analyzer = make_analyzer(tmp_path, parallel_workers=2)

    cached_group = "saber:cached"
    bc_path = saber_paths[cached_group]
    fingerprint = analyzer._tool_artifact_fingerprint("saber", cached_group, bc_path)
    output_dir = tmp_path / ".zscope_svf_cached"
    artifact_path = analyzer._write_saber_artifact(output_dir, [])
    artifact_hash = analyzer._file_hash(artifact_path)
    relpath = analyzer._relative_artifact_path(artifact_path, tmp_path)
    analyzer._write_tool_status(
        "saber",
        cached_group,
        fingerprint,
        status="success",
        timed_out=False,
        artifact_path=relpath,
        artifact_hash=artifact_hash,
    )
    assert analyzer._materialize_group(
        "saber", cached_group, fingerprint, artifact_path, artifact_hash, relpath
    )

    had_failure = analyzer._run_saber_groups(runner, saber_paths, tmp_path)

    assert had_failure is False
    assert runner.calls == ["saber:fresh"]
    assert analyzer._load_tool_status("saber", cached_group).get("status") == "success"


def test_saber_groups_empty_input(tmp_path: Path) -> None:
    analyzer = make_analyzer(tmp_path, parallel_workers=2)
    runner = FakeSaberRunner({})
    assert analyzer._run_saber_groups(runner, {}, tmp_path) is False
    assert runner.calls == []
