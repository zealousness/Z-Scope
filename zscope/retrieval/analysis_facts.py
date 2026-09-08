"""Scan-owned, byte-bounded fact cache with one producer per key."""

from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import Future
import pickle
import hashlib
from pathlib import Path
import threading
from typing import Any, Callable


class AnalysisFactCache:
    def __init__(self, max_bytes: int = 64 * 1024 * 1024):
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._entries: OrderedDict[Any, bytes] = OrderedDict()
        self._pending: dict[Any, Future[Any]] = {}
        self._bytes = 0
        self.computations = 0

    def compute(self, key: Any, producer: Callable[[], Any]) -> Any:
        with self._lock:
            encoded = self._entries.get(key)
            if encoded is not None:
                self._entries.move_to_end(key)
                return pickle.loads(encoded)  # exclusively in-memory, self-produced bytes
            future = self._pending.get(key)
            owner = future is None
            if owner:
                future = Future()
                self._pending[key] = future
                self.computations += 1
        assert future is not None
        if not owner:
            return pickle.loads(future.result())
        try:
            value = producer()
            encoded = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
            with self._lock:
                if len(encoded) <= self.max_bytes:
                    self._entries[key] = encoded
                    self._bytes += len(encoded)
                    while self._bytes > self.max_bytes:
                        _, old = self._entries.popitem(last=False)
                        self._bytes -= len(old)
            future.set_result(encoded)
            return value
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._pending.pop(key, None)


_ATTACH_LOCK = threading.Lock()


def scan_fact_cache(index: Any) -> AnalysisFactCache:
    with _ATTACH_LOCK:
        cache = getattr(index, "_analysis_fact_cache", None)
        if cache is None:
            cache = AnalysisFactCache()
            try:
                setattr(index, "_analysis_fact_cache", cache)
            except (AttributeError, TypeError):
                pass  # Stateless standalone views need no cross-entry owner.
        return cache


def index_context_key(index: Any) -> tuple[Any, ...]:
    """Pin compilation and published-index identity independently of entry scope."""
    command_hash = ""
    raw_path = getattr(index, "compile_commands_path", None)
    if raw_path:
        path = Path(raw_path)
        if not path.is_absolute():
            path = Path(getattr(index, "project_root", ".")) / path
        try:
            stat = path.stat()
            command_hash = scan_fact_cache(index).compute(
                ("compile-context", str(path), stat.st_mtime_ns, stat.st_size),
                lambda: hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        except OSError:
            command_hash = "unavailable:" + str(path)
    backend = getattr(index, "_backend", None)
    clang = getattr(backend, "_clang", None) or backend
    db = getattr(clang, "_db", None)
    get_metadata = getattr(db, "get_metadata", None)
    metadata = []
    if callable(get_metadata):
        for key in ("schema_version", "clang_batch_input", "symbol_context_extractor_version"):
            metadata.append(str(get_metadata(key) or ""))
    return getattr(index, "_index_epoch", 0), command_hash, tuple(metadata)
