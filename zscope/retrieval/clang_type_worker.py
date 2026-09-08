"""Shared clangd session for cooperative, function-scoped type collection."""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Optional

from .clang_derived_cache import DerivedCache, cache_key
from .clang_extractor import ClangExtractor
from .clang_input_watch import InputStampWatch
from .clang_resolution import (
    DerivedResolver,
    _scope_path,
    build_identity,
)
from .clang_type_state import TypeContextUnavailable
from .knowledge_db import KnowledgeDB
from .indexing_runtime import resource_limits, process_tree_rss, process_rss


class TypeCollectionCancelled(BaseException):
    """Control flow: broad resolver error handlers must not swallow cancellation."""


class FunctionTypeCollector:
    def __init__(self, backend: Any):
        self.backend = backend
        self.db = backend._db
        limits = resource_limits()
        self.memory_budget = limits.get("task_memory_budget_bytes")
        self.python_baseline = process_rss(os.getpid()) or 0
        compilation = backend._compile_commands_path
        self.ex = ClangExtractor(
            project_root=backend._source_path,
            clangd_path=shutil.which(backend._clangd_path) or backend._clangd_path,
            compile_commands_dir=Path(compilation).parent if compilation else None,
            max_threads=max(1, min(backend._max_threads, int(limits["cpu_count"]))),
        )
        self.cache: DerivedCache | None = None
        self.resolver: DerivedResolver | None = None
        self.by_name: dict[str, list[dict[str, Any]]] = {}
        self.type_names: set[str] = set()
        self.types_by_identity: dict[str, dict[str, Any]] = {}
        self.closures: dict[str, list[str]] = {}
        self.stamps: dict[Path, tuple[int, int, int, int] | None] = {}
        self.dependencies: dict[str, set[Path]] = {}
        self.attested: dict[str, set[Path]] = {}
        self.scopes: dict[str, set[Path]] = {}
        self.common: set[Path] = set()
        self.watch: Optional[InputStampWatch] = None
        self._scope_cache: "OrderedDict[str, frozenset[Path]]" = OrderedDict()
        self._reverse_edges: Optional[dict[str, set[str]]] = None
        self._gate_clean_time: dict[str, float] = {}
        self._gate_stats: dict[str, int] = {
            "full_scope_checks": 0,
            "scoped_checks": 0,
            "gate_skips": 0,
            "scope_cache_hits": 0,
        }
        self.epoch = ""
        self.reusable = False
        self._cancelled = threading.Event()
        setattr(self.ex, "_type_prepare_checkpoint", self._prepare_checkpoint)

    def _prepare_checkpoint(self) -> None:
        if self._cancelled.is_set():
            raise TypeCollectionCancelled()

    def prepare(self) -> None:
        try:
            self._prepare_checkpoint()
            self.check_resources()
            if not self.ex.start():
                raise TypeContextUnavailable("clangd_unavailable")
            epoch, self.reusable, reason = build_identity(self.ex, self.db)
            self._prepare_checkpoint()
            self.epoch = (
                epoch
                if self.reusable
                else cache_key(
                    [epoch, getattr(self.backend, "_type_ref_cache_nonce", uuid.uuid4().hex)]
                )
            )
            self.stamps = getattr(self.ex, "_derived_input_stamps")
            self.dependencies = getattr(self.ex, "_derived_dependencies_by_source")
            self.attested = getattr(self.ex, "_derived_attested_by_source", None) or {}
            self.scopes = getattr(self.ex, "_derived_invalidation_scope_by_source", None) or {}
            dependency_paths = (
                set().union(*self.dependencies.values()) if self.dependencies else set()
            )
            self.common = {
                p
                for p in self.stamps
                if p not in dependency_paths
                and (
                    p.name in {".clangd", "config.yaml", "compile_commands.json"}
                    or p == Path(self.ex.clangd_path)
                )
            }
            self.watch = InputStampWatch(self.stamps)
            self.check_inputs(None)
            self.cache = DerivedCache(
                Path(self.db._db_path).parent / "clang_type_refs_cache.sqlite3",
                epoch=self.epoch,
            )
            self.resolver = DerivedResolver(self.ex, self.cache)
            self.resolver.cooperative = True
            self.resolver.scope = "function_type_refs"
            self.resolver.reusable = self.reusable
            self.resolver.identity_reason = reason
            self.ex._derived_resolver = self.resolver
            records = self.db.get_type_definition_records()
            self.by_name = self.ex._records_by_name(records)
            self.type_names = set(self.by_name)
            self.types_by_identity = {KnowledgeDB.type_index_name(row): row for row in records}
            files = list(json.loads(self.db.get_metadata("clang_type_refs_fallback") or "{}"))
            self.closures = self.ex._load_include_closures(self.db, files)
        except BaseException:
            self.close()
            raise

    def check_inputs(self, function: dict[str, Any] | None, *, verify: bool = False) -> None:
        # Receipt validation stays a LIVE stat comparison at every task
        # boundary: it decides whether cached rows may be trusted and is the
        # exact invalidation backstop for the scoped stamp gate below.
        if function is not None and self.resolver is not None:
            from .clang_source_snapshot import SourceInputsChanged

            try:
                self.resolver.sources.validate_path(str(function["file_path"]))
                saved = (
                    self.cache.get("function", self._function_key(function)) if self.cache else None
                )
                if saved:
                    self.resolver.sources.validate_receipts(saved.get("source_views", []))
            except SourceInputsChanged as exc:
                raise TypeContextUnavailable("inputs_changed", str(exc)) from exc
        if not self.ex.is_healthy():
            raise TypeContextUnavailable(
                "clangd_unavailable", "Type collector lost its clangd process"
            )
        source = (
            self.ex._resolve_indexed_source_path(str(function["file_path"])) if function else None
        )
        self._check_stamps(source, verify=verify)

    def _check_stamps(self, source: Optional[Path], *, verify: bool = False) -> None:
        """Scope-limited live staleness gate over the session input stamps.

        Three-tier scope resolution keeps the per-function cost proportional
        to the function's own dependency footprint instead of the whole
        project inventory. Pre-flight checks may skip re-verification within
        a short TTL; correctness boundaries pass ``verify=True``, which always
        live-stats the scope. Files actually read are covered exactly by
        receipt validation either way.
        """
        assert self.watch is not None
        if source is None:
            # Session-start verification over the whole inventory, in parallel.
            self._gate_stats["full_scope_checks"] += 1
            if self.watch.changed_parallel(self.stamps.keys()):
                raise TypeContextUnavailable(
                    "inputs_changed", "Source or compilation dependencies changed"
                )
            return
        key = str(source)
        selected = self._gate_scope(source)
        if not verify and selected is not None and self._gate_is_fresh(key):
            self._gate_stats["gate_skips"] += 1
            return
        if selected is None:
            self._gate_stats["full_scope_checks"] += 1
            changed = self.watch.changed_parallel(self.stamps.keys())
        else:
            self._gate_stats["scoped_checks"] += 1
            if len(selected) > 256:
                changed = self.watch.changed_parallel(selected)
            else:
                changed = self.watch.changed(selected)
        if changed:
            raise TypeContextUnavailable(
                "inputs_changed", "Source or compilation dependencies changed"
            )
        self._gate_clean_time[key] = time.monotonic()

    def _gate_is_fresh(self, key: str) -> bool:
        last_time = self._gate_clean_time.get(key)
        return last_time is not None and (time.monotonic() - last_time) < 0.25

    def _gate_scope(self, source: Path) -> Optional[frozenset[Path]]:
        cached = self._scope_cache.get(str(source))
        if cached is not None:
            self._scope_cache.move_to_end(str(source))
            self._gate_stats["scope_cache_hits"] += 1
            return cached
        scope = self._build_gate_scope(source)
        if scope is None:
            return None
        combined = frozenset(scope | self.common)
        self._scope_cache[str(source)] = combined
        if len(self._scope_cache) > 512:
            self._scope_cache.popitem(last=False)
        return combined

    def _build_gate_scope(self, source: Path) -> Optional[set[Path]]:
        key = str(source)
        # 1) Compiler-attested dependency manifest (fresh full depfile).
        deps = self.dependencies.get(key)
        if deps:
            return set(deps)
        # 2) Conservative lexical superset built by build_identity for TUs
        #    without a usable depfile. A superset can only over-invalidate.
        scope = self.scopes.get(key)
        if scope:
            return set(scope)
        # 3) Lazily derived scope for headers and other paths outside the
        #    compilation database: the header's own include closure plus the
        #    sources of the (bounded) TUs that include it. Files actually
        #    read are still covered exactly by receipts validation.
        return self._header_scope(source, key)

    def _header_scope(self, source: Path, key: str) -> Optional[set[Path]]:
        try:
            closure = self.ex._load_include_closures(self.db, [key]).get(key) or []
        except Exception:
            closure = []
        scope = {source}
        scope.update(_scope_path(str(item), self.ex.project_root) for item in closure)
        reverse = self._reverse_include_edges()
        normalize = getattr(self.db, "_normalize_include_graph_path", None)
        if callable(normalize):
            tus = sorted(reverse.get(normalize(key), ()))[:8]
            scope.update(Path(tu) for tu in tus)
        if len(scope) <= 1:
            # Nothing derivable: fall back to the full inventory gate.
            return None
        return scope

    def _reverse_include_edges(self) -> dict[str, set[str]]:
        if self._reverse_edges is not None:
            return self._reverse_edges
        normalize = getattr(self.db, "_normalize_include_graph_path", None)
        reverse: dict[str, set[str]] = {}
        if callable(normalize):
            try:
                rows = self.db._conn.execute(
                    "SELECT source_file, included_file FROM include_edges WHERE is_system = 0"
                ).fetchall()
            except Exception:
                rows = []
            for row in rows:
                included = normalize(str(row["included_file"] or ""))
                if included:
                    reverse.setdefault(included, set()).add(str(row["source_file"] or ""))
        self._reverse_edges = reverse
        return reverse

    def pump(self) -> None:
        if self.cache:
            self.cache.pump()

    def check_resources(self) -> None:
        if self.resolver is not None and not self.ex.is_healthy():
            raise TypeContextUnavailable(
                "clangd_unavailable", "Type collector lost its clangd process"
            )
        process = self.ex.process
        used = process_tree_rss(process.pid) if process is not None else 0
        used = (used or 0) + max(0, (process_rss(os.getpid()) or 0) - self.python_baseline)
        available = resource_limits().get("available_memory_bytes")
        limit = self.memory_budget
        if available is not None:
            current_limit = int((int(available) + used) * 0.75)
            limit = current_limit if limit is None else min(int(limit), current_limit)
        if limit is not None and (int(limit) <= 0 or used > int(limit)):
            raise TypeContextUnavailable(
                "resource_memory_exceeded", "Type collection exceeds the available memory budget"
            )

    def collect(
        self, function: dict[str, Any], checkpoint: Callable[[], None]
    ) -> list[tuple[Any, ...]]:
        assert self.cache is not None and self.resolver is not None
        self.check_inputs(function)
        self.resolver.local.checkpoint = checkpoint
        file = str(function["file_path"])
        source = self.ex._resolve_indexed_source_path(file)
        key = self._function_key(function)
        saved = self.cache.get("function", key)
        if saved is not None:
            rows = []
            for row in saved["rows"]:
                row = list(row)
                row[0] = function["id"]
                if row[2]:
                    target = self.types_by_identity.get(row[2])
                    if target is None:
                        raise TypeContextUnavailable("base_identity_changed")
                    row[1] = target["id"]
                rows.append(tuple(row))
            return rows
        lines = self.ex._read_source_lines(source)
        if lines is None:
            raise TypeContextUnavailable("source_unavailable", str(source))
        stats = self.ex._new_derived_worker_stats("function_type_refs")
        names = self.type_names
        with self.resolver.file(source) as state:
            # The thread's parked stack is the continuation; state is never
            # rebound on a different task's thread or shared by function name.
            state["function_identity"] = function["identity"]
            context = self.ex._new_derived_resolution_caches()
            if self.ex._functions_contain_candidate_identifiers([function], lines, names):
                with self.resolver.lease(source) as opened:
                    if not opened:
                        raise TypeContextUnavailable("document_unavailable", str(source))
                    context.update(
                        self.ex._get_file_semantic_context(source, lines, enabled=True, stats=stats)
                    )
                checkpoint()

            def collect() -> list[tuple[Any, ...]]:
                return self.ex._collect_function_type_refs(
                    function,
                    file,
                    source,
                    lines,
                    self.by_name,
                    names,
                    self.closures.get(file, [file]),
                    context,
                    stats,
                )

            rows = collect()
            if state["pending"]:
                self.resolver.flush(state)
                rows = collect()
            if state["transient"] or stats.get("_incomplete"):
                raise TypeContextUnavailable(
                    "type_references_incomplete", str(stats.get("unresolved_reasons", {}))
                )
            checkpoint()
            # Correctness boundary: a live verification after collection, so
            # rows are only cached against inputs verified unchanged.
            self.check_inputs(function, verify=True)
            rows = sorted(set(rows), key=repr)
        self.cache.put(
            "function", key, {"rows": rows, "source_views": self.resolver.sources.receipts(state)}
        )
        return rows

    @staticmethod
    def _function_key(function: dict[str, Any]) -> str:
        return cache_key(
            [function["generation"], function["identity"], function["context"], "source-views-v1"]
        )

    def metrics(self) -> dict[str, Any]:
        return {
            "cache": self.cache.snapshot() if self.cache else {},
            "sources": self.resolver.sources.snapshot() if self.resolver else {},
            "rpc": {
                name: self.ex.get_request_metrics(name)
                for name in (
                    "textDocument/semanticTokens/full",
                    "textDocument/symbolInfo",
                    "textDocument/definition",
                    "textDocument/declaration",
                    "textDocument/references",
                )
            },
            "memory": self.resolver.memory_snapshot() if self.resolver else {},
            "inputs": dict(
                self._gate_stats,
                watch=dict(self.watch.stats) if self.watch is not None else {},
                scopes_prebuilt=len(self.scopes),
                dependencies_attested=len(self.attested),
                dependencies_total=len(self.dependencies),
            ),
        }

    def interrupt(self) -> None:
        # Called only for resource handoff/close, never for a waiter timeout.
        self._cancelled.set()
        self.ex.cancel_pending_requests()

    def close(self) -> None:
        self.watch = None
        self.ex._derived_resolver = None
        self.ex.stop()
        if self.cache:
            self.cache.checkpoint()
            self.cache.close()
            self.cache = None
