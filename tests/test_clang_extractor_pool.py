"""Clangd shard pool tests (P1-M3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from zscope.retrieval import clang_extractor_pool as pool_module
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_extractor_pool import ClangExtractorPool
from zscope.retrieval.knowledge_db import KnowledgeDB


class FakeShard:
    """Duck-typed ClangExtractor shard; records every pool interaction."""

    instances: List["FakeShard"] = []

    def __init__(
        self,
        *,
        project_root: Path,
        clangd_path: str,
        compile_commands_dir: Optional[Path],
        max_threads: int,
    ):
        self.project_root = project_root
        self.clangd_path = clangd_path
        self.compile_commands_dir = compile_commands_dir
        self.max_threads = max_threads
        self.started = False
        self.stopped = False
        self.seeded: List[List[Path]] = []
        self.deleted: List[List[Path]] = []
        self.wait_calls: List[int] = []
        self.collect_calls: List[str] = []
        self.call_edge_work: List[Tuple[Any, ...]] = []
        self.closed_documents: List[str] = []
        self.derived_calls: List[Dict[str, Any]] = []
        FakeShard.instances.append(self)

    # lifecycle
    def start(self) -> bool:
        self.started = True
        return True

    def stop(self) -> None:
        self.stopped = True

    def is_healthy(self) -> bool:
        return self.started and not self.stopped

    def wait_for_indexing(self, timeout: int = 120, idle_threshold: float = 5.0) -> bool:
        self.wait_calls.append(timeout)
        return True

    def seed_project_file_index(self, file_paths: List[Path]) -> None:
        self.seeded.append(list(file_paths))

    def notify_files_deleted(self, file_paths: List[Path]) -> None:
        self.deleted.append(list(file_paths))

    def get_request_metrics(self, method: str) -> Dict[str, Any]:
        return {"count": 1, "timeouts": 0, "average_latency_ms": 2.0, "p95_latency_ms": 4.0}

    # extraction
    def _collect_tu_facts(
        self,
        file_path: Path,
        db: KnowledgeDB,
        tu_id: int,
        *,
        defer_call_queries: bool = False,
    ) -> Optional[Dict[str, Any]]:
        self.collect_calls.append(str(file_path))
        return {
            "func_rows": [],
            "call_rows": [],
            "type_rows": [],
            "global_rows": [],
            "macro_rows": [],
            "include_rows": [],
            "_call_work": [(str(file_path), "callee", 1, 0, {})],
            "_deferred_document_path": str(file_path),
        }

    def _extract_deferred_call_edges(self, work: Tuple[Any, ...]) -> List[Tuple[Any, ...]]:
        self.call_edge_work.append(work)
        return []

    def close_document(self, file_path: Path) -> None:
        self.closed_documents.append(str(file_path))

    # derived delegation
    def begin_derived_rebuild_session(self) -> None:
        self.derived_calls.append({"method": "begin"})

    def end_derived_rebuild_session(self) -> None:
        self.derived_calls.append({"method": "end"})

    def rebuild_function_derived_refs(
        self, db: KnowledgeDB, *, use_staging: bool = False
    ) -> int:
        self.derived_calls.append({"method": "derived", "use_staging": use_staging})
        return 7

    def get_last_derived_stats(self, index_name: str) -> Dict[str, Any]:
        return {"rows": 7}

    @staticmethod
    def _publish_tu_facts(db: KnowledgeDB, tu_id: int, **facts: Any) -> None:
        with db.replace_tu_facts_transaction(tu_id):
            pass

    @staticmethod
    def _compute_file_hash(file_path: Path) -> str:
        return "fake-hash-" + str(file_path)


@pytest.fixture()
def fake_shards(monkeypatch):
    FakeShard.instances = []
    monkeypatch.setattr(pool_module, "ClangExtractor", FakeShard)
    return FakeShard


def make_files(tmp_path: Path, count: int, subdir: str = "src") -> List[Path]:
    directory = tmp_path / subdir
    directory.mkdir(parents=True, exist_ok=True)
    files = []
    for i in range(count):
        fp = directory / f"file{i}.c"
        fp.write_text(f"int f{i}(void) {{ return {i}; }}\n", encoding="utf-8")
        files.append(fp)
    return files


def test_shard_count_from_env(monkeypatch) -> None:
    monkeypatch.delenv("Z_SCOPE_CLANGD_SHARDS", raising=False)
    assert ClangExtractorPool.shard_count_from_env() == 1
    monkeypatch.setenv("Z_SCOPE_CLANGD_SHARDS", "3")
    assert ClangExtractorPool.shard_count_from_env() == 3
    monkeypatch.setenv("Z_SCOPE_CLANGD_SHARDS", "9")
    assert ClangExtractorPool.shard_count_from_env() == 4
    monkeypatch.setenv("Z_SCOPE_CLANGD_SHARDS", "0")
    assert ClangExtractorPool.shard_count_from_env() == 1
    monkeypatch.setenv("Z_SCOPE_CLANGD_SHARDS", "not-a-number")
    assert ClangExtractorPool.shard_count_from_env() == 1


def test_pool_lifecycle_broadcasts(tmp_path: Path, fake_shards) -> None:
    pool = ClangExtractorPool(
        project_root=tmp_path,
        clangd_path="clangd",
        compile_commands_dir=None,
        max_threads=8,
        shard_count=3,
    )
    assert len(pool._shards) == 3
    # per-shard clangd worker budget keeps total concurrency bounded
    assert all(shard.max_threads == 3 for shard in pool._shards)

    assert pool.start() is True
    assert all(shard.started for shard in pool._shards)
    assert pool.is_healthy() is True

    files = make_files(tmp_path, 2)
    pool.seed_project_file_index(files)
    pool.notify_files_deleted(files)
    assert all(len(shard.seeded) == 1 for shard in pool._shards)
    assert all(len(shard.deleted) == 1 for shard in pool._shards)

    pool.stop()
    assert all(shard.stopped for shard in pool._shards)


def test_run_batch_partitions_and_publishes(tmp_path: Path, fake_shards) -> None:
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    files = make_files(tmp_path, 4)
    pool = ClangExtractorPool(
        project_root=tmp_path,
        clangd_path="clangd",
        compile_commands_dir=None,
        max_threads=8,
        shard_count=2,
    )
    assert pool.start() is True

    stats = pool.run_batch_extraction(files, db, batch_size=50)

    assert stats["success"] == 4
    assert stats["failed"] == 0
    assert stats["skipped"] == 0
    collected = sum(len(shard.collect_calls) for shard in fake_shards.instances)
    assert collected == 4
    # same-directory TUs land on one shard (preamble locality)
    assert sum(len(shard.collect_calls) > 0 for shard in fake_shards.instances) == 1
    for tus in db.get_all_tus():
        assert tus["status"] == "indexed"
    # deferred call edges were routed back to the shard that owns the doc
    owning = [shard for shard in fake_shards.instances if shard.collect_calls]
    idle = [shard for shard in fake_shards.instances if not shard.collect_calls]
    assert all(len(shard.call_edge_work) == 4 for shard in owning)
    assert all(len(shard.call_edge_work) == 0 for shard in idle)
    assert sum(len(shard.closed_documents) for shard in fake_shards.instances) == 4
    assert all(len(shard.closed_documents) == 0 for shard in idle)


def test_partition_items_groups_by_directory(tmp_path: Path, fake_shards) -> None:
    import zlib

    pool = ClangExtractorPool(
        project_root=tmp_path,
        clangd_path="clangd",
        compile_commands_dir=None,
        max_threads=4,
        shard_count=2,
    )
    # crc32 is stable, so two of many directories must land on both shards
    dirs = [tmp_path / f"dir{i}" for i in range(20)]
    for directory in dirs:
        directory.mkdir(exist_ok=True)
    by_shard: Dict[int, List[Path]] = {0: [], 1: []}
    for directory in dirs:
        fp = directory / "a.c"
        fp.write_text("int a(void) { return 0; }\n", encoding="utf-8")
        shard = zlib.crc32(str(directory).encode("utf-8", "surrogatepass")) % 2
        by_shard[shard].append(fp)
    assert by_shard[0] and by_shard[1]

    items = [(fp, i + 1) for fps in by_shard.values() for i, fp in enumerate(fps)]
    partitioned = pool._partition_items(items)
    assert sum(len(part) for part in partitioned) == len(items)
    for shard_index, part in enumerate(partitioned):
        parents = {fp.parent for fp, _tu in part}
        expected = set(by_shard[shard_index]) and {
            fp.parent for fp in by_shard[shard_index]
        }
        if part:
            assert parents == expected


def test_run_batch_respects_prescanned_unchanged(tmp_path: Path, fake_shards) -> None:
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    files = make_files(tmp_path, 2)
    pool = ClangExtractorPool(
        project_root=tmp_path,
        clangd_path="clangd",
        compile_commands_dir=None,
        max_threads=4,
        shard_count=2,
    )
    assert pool.start() is True

    prescanned: Dict[str, Tuple[int, bool]] = {}
    for fp in files:
        tu_id, changed = db.register_tu_hash(str(fp), "same-hash")
        assert changed is True
        # backend prescan reports unchanged TUs as (tu_id, False)
        prescanned[str(fp.resolve())] = (tu_id, False)

    stats = pool.run_batch_extraction(files, db, batch_size=10, prescanned_tus=prescanned)
    assert stats["success"] == 0
    assert stats["skipped"] == 2
    assert stats["failed"] == 0
    assert all(shard.collect_calls == [] for shard in fake_shards.instances)


def test_wait_for_indexing_shares_deadline(tmp_path: Path, fake_shards) -> None:
    pool = ClangExtractorPool(
        project_root=tmp_path,
        clangd_path="clangd",
        compile_commands_dir=None,
        max_threads=8,
        shard_count=2,
    )
    assert pool.wait_for_indexing(timeout=120, idle_threshold=3.0) is True
    timeouts = [shard.wait_calls[-1] for shard in pool._shards]
    assert all(0 < timeout <= 120 for timeout in timeouts)


def test_derived_rebuilds_delegate_to_primary_shard(tmp_path: Path, fake_shards) -> None:
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    pool = ClangExtractorPool(
        project_root=tmp_path,
        clangd_path="clangd",
        compile_commands_dir=None,
        max_threads=4,
        shard_count=2,
    )
    pool.begin_derived_rebuild_session()
    result = pool.rebuild_function_derived_refs(db, use_staging=True)
    pool.end_derived_rebuild_session()

    assert result == 7
    primary = pool._shards[0]
    assert [call["method"] for call in primary.derived_calls] == [
        "begin",
        "derived",
        "end",
    ]
    # secondary shard stays untouched by derived rebuilds
    assert pool._shards[1].derived_calls == []


def test_backend_wiring_uses_pool_when_env_set(tmp_path: Path, fake_shards, monkeypatch) -> None:
    monkeypatch.setenv("Z_SCOPE_CLANGD_SHARDS", "2")
    backend = ClangBackend(clangd_path="clangd", db_path=str(tmp_path / "x.db"))
    backend._source_path = tmp_path
    backend._compile_commands_path = None
    assert backend._ensure_extractor() is True
    assert isinstance(backend._extractor, ClangExtractorPool)
    backend._extractor.stop()

    monkeypatch.setenv("Z_SCOPE_CLANGD_SHARDS", "1")
    backend2 = ClangBackend(clangd_path="clangd", db_path=str(tmp_path / "y.db"))
    backend2._source_path = tmp_path
    backend2._compile_commands_path = None
    import zscope.retrieval.clang_backend as backend_module

    monkeypatch.setattr(backend_module, "ClangExtractor", FakeShard)
    assert backend2._ensure_extractor() is True
    assert not isinstance(backend2._extractor, ClangExtractorPool)
    backend2._extractor.stop()
