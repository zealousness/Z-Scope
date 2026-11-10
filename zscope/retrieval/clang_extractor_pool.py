"""Optional clangd shards; collect concurrently and publish on one DB thread."""

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from .clang_extractor import ClangExtractor
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)


class _CollectedFacts:
    """Record the existing extractor's writes without sharing SQLite connections."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, tuple, dict]] = []
        self._conn = self
        self._next_type = -1

    def insert_type(self, *args, **kwargs) -> int:
        token = self._next_type
        self._next_type -= 1
        self.calls.append(("insert_type", args, {**kwargs, "_token": token}))
        return token

    def __getattr__(self, name: str) -> Any:
        if name not in {
            "insert_type_member",
            "insert_functions_batch",
            "insert_call_edges_batch",
            "insert_macro_definitions_batch",
            "mark_tu_indexed",
            "execute",
        }:
            raise AttributeError(name)

        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))

        return record

    def publish(self, db: KnowledgeDB) -> None:
        type_ids = {}
        for name, args, kwargs in self.calls:
            kwargs = dict(kwargs)
            if name == "insert_type":
                token = kwargs.pop("_token")
                type_ids[token] = db.insert_type(*args, **kwargs)
            elif name == "insert_type_member":
                db.insert_type_member(type_ids[args[0]], *args[1:], **kwargs)
            elif name == "execute":
                db._conn.execute(*args, **kwargs)
            else:
                getattr(db, name)(*args, **kwargs)


class ClangExtractorPool:
    def __init__(
        self,
        project_root: Path,
        clangd_path: str = "clangd",
        compile_commands_dir: Optional[Path] = None,
        max_threads: int = 8,
        shard_count: int = 2,
    ) -> None:
        self._shards = [
            ClangExtractor(
                project_root,
                clangd_path,
                compile_commands_dir,
                max_threads=max(1, max_threads // max(2, min(shard_count, 4))),
            )
            for _ in range(max(2, min(shard_count, 4)))
        ]

    @staticmethod
    def shard_count_from_env() -> int:
        raw = os.environ.get("Z_SCOPE_CLANGD_SHARDS", "1")
        try:
            return max(1, min(int(raw), 4))
        except ValueError:
            raise ValueError("Z_SCOPE_CLANGD_SHARDS must be an integer between 1 and 4") from None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._shards[0], name)

    def start(self) -> bool:
        for shard in self._shards:
            if not shard.start():
                self.stop()
                return False
        return True

    def stop(self) -> None:
        for shard in self._shards:
            shard.stop()

    def wait_for_indexing(self, timeout: float = 120, idle_threshold: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0, timeout)
        return all(
            shard.wait_for_indexing(max(0, deadline - time.monotonic()), idle_threshold)
            for shard in self._shards
        )

    def run_batch_extraction(
        self,
        file_list: List[Path],
        db: KnowledgeDB,
        batch_size: int = 50,
        progress_cb: Optional[Callable] = None,
        prescanned_tus: Optional[Dict[str, Tuple[int, bool]]] = None,
    ) -> Dict[str, int]:
        stats = dict(total=len(file_list), success=0, failed=0, skipped=0)
        prescanned_tus = prescanned_tus or {}
        batch_size = max(1, batch_size)

        def collect(
            shard: ClangExtractor, work: List[Tuple[Path, int]]
        ) -> List[Tuple[Path, int, bool, _CollectedFacts]]:
            results = []
            for path, tu_id in work:
                facts = _CollectedFacts()
                try:
                    ok = shard.extract_tu(path, cast(Any, facts), tu_id)
                except Exception:
                    logger.exception("Failed to extract %s", path)
                    ok = False
                finally:
                    shard.close_document(path)
                results.append((path, tu_id, ok, facts))
            return results

        with ThreadPoolExecutor(max_workers=len(self._shards)) as executor:
            for offset in range(0, len(file_list), batch_size):
                partitions: List[List[Tuple[Path, int]]] = [[] for _ in self._shards]
                directory_owner: Dict[Path, int] = {}
                for raw in file_list[offset : offset + batch_size]:
                    path = Path(raw).resolve()
                    scan = prescanned_tus.get(str(path))
                    if scan is None:
                        scan = db.register_tu_hash(
                            str(path), ClangExtractor._compute_file_hash(path)
                        )
                    tu_id, changed = scan
                    if not changed:
                        stats["skipped"] += 1
                        continue
                    owner = directory_owner.setdefault(
                        path.parent, len(directory_owner) % len(self._shards)
                    )
                    capacity = max(
                        1,
                        (min(batch_size, len(file_list) - offset) + len(self._shards) - 1)
                        // len(self._shards),
                    )
                    if len(partitions[owner]) >= capacity:
                        owner = min(range(len(partitions)), key=lambda i: len(partitions[i]))
                    partitions[owner].append((path, tu_id))
                futures = [
                    executor.submit(collect, shard, work)
                    for shard, work in zip(self._shards, partitions)
                    if work
                ]
                results = [item for future in futures for item in future.result()]
                for path, tu_id, ok, facts in sorted(results, key=lambda item: str(item[0])):
                    if ok:
                        db.purge_tu_data(tu_id)
                        facts.publish(db)
                        stats["success"] += 1
                        if progress_cb:
                            progress_cb(path)
                    else:
                        stats["failed"] += 1
                db.commit()
        return stats
