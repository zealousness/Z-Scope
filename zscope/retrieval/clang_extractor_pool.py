"""Multi-instance clangd sharding pool for base TU extraction (P1-M3).

A single clangd process serializes AST work behind its internal scheduler, so
large repositories leave cores idle behind that bottleneck.  This pool runs K
independent ClangExtractor instances (each owning one clangd process) and
partitions translation units by parent directory so per-TU preambles stay warm
on the shard that owns the directory.  Publishing stays single-writer: facts
are collected concurrently per shard and flushed through the caller's
KnowledgeDB batch transaction on the invoking thread.

Derived index rebuilds intentionally keep their existing correctness model and
delegate to the primary shard.

The pool is opt-in via Z_SCOPE_CLANGD_SHARDS (default 1 = plain
ClangExtractor); values are clamped to 2..4 when the pool is enabled.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .clang_extractor import ClangExtractor
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)

_TRACKED_METHODS = (
    "textDocument/documentSymbol",
    "textDocument/prepareCallHierarchy",
    "callHierarchy/outgoingCalls",
    "textDocument/definition",
)

_MAX_SHARDS = 4
_DERIVED_SHARD_INDEX = 0

_Collected = Tuple[Path, int, Optional[Dict[str, Any]], bool, Optional[Exception]]


class ClangExtractorPool:
    """Fan base TU extraction across several independent clangd processes."""

    def __init__(
        self,
        *,
        project_root: Path,
        clangd_path: str,
        compile_commands_dir: Optional[Path],
        max_threads: int,
        shard_count: int,
    ):
        shard_count = max(2, min(int(shard_count), _MAX_SHARDS))
        total_threads = max(1, int(max_threads or 1))
        per_shard_threads = max(2, -(-total_threads // shard_count))
        self._shards: List[ClangExtractor] = [
            ClangExtractor(
                project_root=project_root,
                clangd_path=clangd_path,
                compile_commands_dir=compile_commands_dir,
                max_threads=per_shard_threads,
            )
            for _ in range(shard_count)
        ]
        self._max_threads = total_threads
        self._last_base_stats: Dict[str, Any] = {}

    @staticmethod
    def shard_count_from_env() -> int:
        """Resolve the configured shard count; 1 keeps the plain extractor."""
        raw = os.environ.get("Z_SCOPE_CLANGD_SHARDS", "").strip()
        if not raw:
            return 1
        try:
            value = int(raw)
        except ValueError:
            logger.warning("Invalid Z_SCOPE_CLANGD_SHARDS=%r; using 1 shard", raw)
            return 1
        if value <= 1:
            return 1
        return min(value, _MAX_SHARDS)

    def start(self) -> bool:
        started: List[ClangExtractor] = []
        for shard in self._shards:
            if shard.start():
                started.append(shard)
            else:
                break
        if len(started) != len(self._shards):
            for shard in started:
                try:
                    shard.stop()
                except Exception:
                    logger.debug("Failed to stop shard during pool start rollback")
            return False
        return True

    def stop(self) -> None:
        for shard in self._shards:
            try:
                shard.stop()
            except Exception as stop_exc:
                logger.debug("Failed to stop pool shard: %s", stop_exc)

    def is_healthy(self) -> bool:
        return bool(self._shards) and all(shard.is_healthy() for shard in self._shards)

    def wait_for_indexing(self, timeout: int = 120, idle_threshold: float = 5.0) -> bool:
        """Wait until every shard reports an idle index within one deadline."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        for shard in self._shards:
            remaining = int(max(0.0, deadline - time.monotonic()))
            if not shard.wait_for_indexing(timeout=remaining, idle_threshold=idle_threshold):
                return False
        return True

    def seed_project_file_index(self, file_paths: List[Path]) -> None:
        for shard in self._shards:
            shard.seed_project_file_index(file_paths)

    def notify_files_deleted(self, file_paths: List[Path]) -> None:
        for shard in self._shards:
            shard.notify_files_deleted(file_paths)

    def run_batch_extraction(
        self,
        file_list: List[Path],
        db: KnowledgeDB,
        batch_size: int = 50,
        progress_cb: Optional[Callable] = None,
        prescanned_tus: Optional[Dict[str, Tuple[int, bool]]] = None,
        index_barrier: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, int]:
        """Extract changed TUs with per-shard clangd instances."""
        started_at = time.monotonic()
        metrics_before = {method: self._sum_request_metrics(method) for method in _TRACKED_METHODS}
        stats: Dict[str, int] = {
            "total": len(file_list),
            "success": 0,
            "failed": 0,
            "skipped": 0,
        }
        prescanned_tus = prescanned_tus or {}
        changed_tu_count = 0
        max_workers_seen = 0

        for i in range(0, len(file_list), batch_size):
            batch = list(file_list[i : i + batch_size])
            logger.info(
                "Processing batch %d/%d (%d files)",
                i // batch_size + 1,
                (len(file_list) + batch_size - 1) // batch_size,
                len(batch),
            )
            work_items: List[Tuple[Path, int]] = []
            for fp in batch:
                fp = Path(fp).resolve()
                tu_scan = prescanned_tus.get(str(fp))
                if tu_scan is None:
                    file_hash = ClangExtractor._compute_file_hash(fp)
                    tu_id, changed = db.register_tu_hash(str(fp), file_hash)
                else:
                    tu_id, changed = tu_scan
                if not changed:
                    stats["skipped"] += 1
                    continue
                work_items.append((fp, int(tu_id)))
            if not work_items:
                logger.info(
                    "Batch complete. Progress: %d extracted, %d skipped, %d failed",
                    stats["success"],
                    stats["skipped"],
                    stats["failed"],
                )
                continue
            changed_tu_count += len(work_items)

            collected = self._collect_across_shards(work_items, db)
            max_workers_seen = max(
                max_workers_seen,
                int(collected.get("max_workers") or 0),
            )
            self._extract_calls_across_shards(
                collected["shards"], index_barrier
            )
            published, failed = self._publish_batch(
                db, collected["shards"], progress_cb
            )
            stats["success"] += published
            stats["failed"] += failed
            logger.info(
                "Batch complete. Progress: %d extracted, %d skipped, %d failed",
                stats["success"],
                stats["skipped"],
                stats["failed"],
            )

        elapsed_seconds = max(0.0, time.monotonic() - started_at)
        self._last_base_stats = {
            "files_total": len(file_list),
            "files_changed": changed_tu_count,
            "files_extracted": stats["success"],
            "files_skipped": stats["skipped"],
            "files_failed": stats["failed"],
            "max_workers": max_workers_seen or len(self._shards),
            "shard_count": len(self._shards),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "lsp_requests": {
                method: self._aggregate_request_metrics(
                    method,
                    metrics_before[method],
                )
                for method in _TRACKED_METHODS
            },
        }
        return stats

    def _collect_across_shards(
        self,
        work_items: Sequence[Tuple[Path, int]],
        db: KnowledgeDB,
    ) -> Dict[str, Any]:
        """Collect TU facts on the shard that owns each work item."""
        partitioned = self._partition_items(work_items)
        results_by_shard: List[List[_Collected]] = [
            [] for _ in range(len(self._shards))
        ]
        workers_per_shard = max(1, -(-self._max_threads // len(self._shards)))

        def run_shard(shard_index: int) -> None:
            shard = self._shards[shard_index]
            items = partitioned[shard_index]
            if not items:
                return

            def collect_one(item: Tuple[Path, int]) -> _Collected:
                fp, tu_id = item
                try:
                    facts = shard._collect_tu_facts(
                        fp,
                        db,
                        tu_id,
                        defer_call_queries=True,
                    )
                    return fp, tu_id, facts, facts is not None, None
                except Exception as exc:
                    return fp, tu_id, None, False, exc

            if len(items) <= 1 or workers_per_shard <= 1:
                shard_results = [collect_one(item) for item in items]
            else:
                with ThreadPoolExecutor(
                    max_workers=min(workers_per_shard, len(items)),
                    thread_name_prefix=f"ClangShard{shard_index}",
                ) as executor:
                    shard_results = list(executor.map(collect_one, items))
            results_by_shard[shard_index] = shard_results

        threads = [
            threading.Thread(
                target=run_shard,
                args=(shard_index,),
                name=f"ClangPoolShard{shard_index}",
            )
            for shard_index in range(len(self._shards))
            if partitioned[shard_index]
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assigned = sum(len(items) for items in partitioned)
        return {
            "shards": results_by_shard,
            "max_workers": min(max(1, assigned), self._max_threads),
        }

    def _extract_calls_across_shards(
        self,
        results_by_shard: List[List[_Collected]],
        index_barrier: Optional[Callable[[], bool]],
    ) -> bool:
        """Extract deferred call edges on the shard that owns each document."""
        barrier_ok = True
        if index_barrier is not None:
            barrier_ok = bool(index_barrier())
            if not barrier_ok:
                logger.error("clangd indexing did not complete before call extraction")
        shard_has_calls = any(
            self._call_work(facts)
            for shard_results in results_by_shard
            for _fp, _tu, facts, ok, _err in shard_results
            if ok
        )
        if shard_has_calls and index_barrier is None:
            barrier_ok = self.wait_for_indexing(timeout=120, idle_threshold=3.0)
            if not barrier_ok:
                logger.error("clangd indexing did not complete before call extraction")

        failures = [False]

        def run_shard(shard_index: int) -> None:
            shard = self._shards[shard_index]
            shard_results = results_by_shard[shard_index]
            call_tasks: List[Tuple[Any, ...]] = []
            deferred_documents: List[Path] = []
            task_owner: List[int] = []
            for position, (_fp, _tu_id, facts, ok, _error) in enumerate(shard_results):
                if not ok or facts is None:
                    continue
                work = facts.pop("_call_work", [])
                deferred_path = facts.pop("_deferred_document_path", None)
                if deferred_path is not None:
                    deferred_documents.append(Path(deferred_path))
                if work and barrier_ok:
                    task_owner.extend([position] * len(work))
                    call_tasks.extend(work)
            if not call_tasks:
                return
            try:
                workers = max(
                    1,
                    min(self._max_threads // len(self._shards) or 1, len(call_tasks)),
                )
                if workers <= 1:
                    materialized = [
                        shard._extract_deferred_call_edges(work) for work in call_tasks
                    ]
                else:
                    with ThreadPoolExecutor(
                        max_workers=workers,
                        thread_name_prefix=f"ClangShardCalls{shard_index}",
                    ) as executor:
                        materialized = list(
                            executor.map(
                                shard._extract_deferred_call_edges,
                                call_tasks,
                            )
                        )
                rows_by_position: Dict[int, List[Tuple[Any, ...]]] = {}
                for position, rows in zip(task_owner, materialized):
                    rows_by_position.setdefault(position, []).extend(rows)
                for position, rows in rows_by_position.items():
                    _fp, _tu_id, facts, ok, _error = shard_results[position]
                    if ok and facts is not None:
                        facts["call_rows"].extend(rows)
            except Exception as exc:
                logger.error(
                    "Deferred call extraction failed on shard %d: %s", shard_index, exc
                )
                failures[0] = True
            finally:
                for document_path in deferred_documents:
                    try:
                        shard.close_document(document_path)
                    except Exception as close_exc:
                        logger.debug(
                            "Failed to close deferred document on shard %d: %s",
                            shard_index,
                            close_exc,
                        )

        threads = [
            threading.Thread(
                target=run_shard,
                args=(shard_index,),
                name=f"ClangPoolCalls{shard_index}",
            )
            for shard_index in range(len(self._shards))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return barrier_ok and not failures[0]

    @staticmethod
    def _call_work(facts: Optional[Dict[str, Any]]) -> List[Tuple[Any, ...]]:
        if not facts:
            return []
        work = facts.get("_call_work") or []
        return list(work) if isinstance(work, list) else []

    def _publish_batch(
        self,
        db: KnowledgeDB,
        results_by_shard: List[List[_Collected]],
        progress_cb: Optional[Callable],
    ) -> Tuple[int, int]:
        """Publish every collected TU through one single-writer transaction."""
        collected: List[_Collected] = []
        for shard_results in results_by_shard:
            collected.extend(shard_results)
        published: List[Path] = []
        failed = 0
        batch_transaction = getattr(db, "replace_tu_facts_batch_transaction", None)
        try:
            if callable(batch_transaction):
                with batch_transaction():
                    failed = self._publish_collected(db, collected, published)
            else:
                failed = self._publish_collected(db, collected, published)
        except Exception as exc:
            logger.error("Failed to commit TU batch: %s", exc)
            failed += len(published)
            published.clear()
        if progress_cb:
            for fp in published:
                progress_cb(fp)
        return len(published), failed

    @staticmethod
    def _publish_collected(
        db: KnowledgeDB,
        collected: Sequence[_Collected],
        published: List[Path],
    ) -> int:
        failed = 0
        for fp, tu_id, facts, ok, error in collected:
            if error is not None:
                logger.error("Failed to collect %s: %s", fp, error)
            if not ok or facts is None:
                failed += 1
                continue
            try:
                ClangExtractor._publish_tu_facts(db, tu_id, **facts)
            except Exception as exc:
                logger.error("Failed to publish %s: %s", fp, exc)
                failed += 1
                continue
            published.append(fp)
        return failed

    def _partition_items(
        self,
        work_items: Sequence[Tuple[Path, int]],
    ) -> List[List[Tuple[Path, int]]]:
        """Group items by parent directory so preambles stay warm per shard."""
        shard_count = len(self._shards)
        partitioned: List[List[Tuple[Path, int]]] = [[] for _ in range(shard_count)]
        for fp, tu_id in work_items:
            key = zlib.crc32(str(fp.parent).encode("utf-8", "surrogatepass"))
            partitioned[key % shard_count].append((fp, tu_id))
        return partitioned

    def begin_derived_rebuild_session(self) -> None:
        self._shards[_DERIVED_SHARD_INDEX].begin_derived_rebuild_session()

    def end_derived_rebuild_session(self) -> None:
        self._shards[_DERIVED_SHARD_INDEX].end_derived_rebuild_session()

    def rebuild_function_derived_refs(
        self,
        db: KnowledgeDB,
        *,
        use_staging: bool = False,
    ) -> int:
        return self._shards[_DERIVED_SHARD_INDEX].rebuild_function_derived_refs(
            db,
            use_staging=use_staging,
        )

    def rebuild_function_symbol_refs(
        self,
        db: KnowledgeDB,
        *,
        use_staging: bool = False,
    ) -> int:
        return self._shards[_DERIVED_SHARD_INDEX].rebuild_function_symbol_refs(
            db,
            use_staging=use_staging,
        )

    def rebuild_function_type_refs(
        self,
        db: KnowledgeDB,
        *,
        use_staging: bool = False,
    ) -> int:
        return self._shards[_DERIVED_SHARD_INDEX].rebuild_function_type_refs(
            db,
            use_staging=use_staging,
        )

    def get_last_derived_stats(self, index_name: str) -> Dict[str, Any]:
        return self._shards[_DERIVED_SHARD_INDEX].get_last_derived_stats(index_name)

    def _sum_request_metrics(self, method: str) -> Dict[str, float]:
        totals = {"count": 0.0, "timeouts": 0.0}
        for shard in self._shards:
            metrics = shard.get_request_metrics(method)
            totals["count"] += float(metrics.get("count") or 0)
            totals["timeouts"] += float(metrics.get("timeouts") or 0)
        return totals

    def _aggregate_request_metrics(
        self,
        method: str,
        before: Dict[str, float],
    ) -> Dict[str, Any]:
        count = 0.0
        timeouts = 0.0
        latency_weighted = 0.0
        p95 = 0.0
        for shard in self._shards:
            metrics = shard.get_request_metrics(method)
            shard_count = max(0.0, float(metrics.get("count") or 0))
            count += shard_count
            timeouts += float(metrics.get("timeouts") or 0)
            latency_weighted += float(metrics.get("average_latency_ms") or 0.0) * shard_count
            p95 = max(p95, float(metrics.get("p95_latency_ms") or 0.0))
        request_count = max(0.0, count - float(before.get("count") or 0.0))
        timeout_count = max(0.0, timeouts - float(before.get("timeouts") or 0.0))
        average = latency_weighted / count if count > 0 else 0.0
        return {
            "count": int(request_count),
            "timeouts": int(timeout_count),
            "average_latency_ms": round(average, 3),
            "p95_latency_ms": round(p95, 3),
        }
