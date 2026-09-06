"""Bounded derived cache with a caller-owned SQLite broker.

Workers never use SQLite, including for reads. The scheduling thread services
their bounded requests while waiting for file jobs. A temporary database gives
the same eviction semantics when persistent dependency identity is unavailable.
"""

from __future__ import annotations

import hashlib
import json
import queue
import sqlite3
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Callable, Optional


def cache_key(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def encode_value(value: Any) -> Any:
    if isinstance(value, Path):
        return ["path", str(value)]
    if isinstance(value, tuple):
        return ["tuple", [encode_value(item) for item in value]]
    if isinstance(value, list):
        return ["list", [encode_value(item) for item in value]]
    if isinstance(value, dict):
        return ["dict", [[encode_value(k), encode_value(v)] for k, v in value.items()]]
    return ["scalar", value]


def decode_value(value: Any) -> Any:
    kind, data = value
    if kind == "path":
        return Path(data)
    if kind == "tuple":
        return tuple(decode_value(item) for item in data)
    if kind == "list":
        return [decode_value(item) for item in data]
    if kind == "dict":
        return {decode_value(k): decode_value(v) for k, v in data}
    return data


class DerivedCache:
    SCHEMA_VERSION = 1

    def __init__(self, path: Optional[Path] = None, *, epoch: str = "", max_bytes: int = 32 << 20):
        self.owner = threading.get_ident()
        self.max_bytes = max(0, max_bytes)
        self._hot: OrderedDict[tuple[str, str], bytes] = OrderedDict()
        self._bytes = 0
        self._requests: queue.Queue[tuple[Callable[[], Any], Future[Any]]] = queue.Queue(32)
        self._lock = threading.RLock()
        self._inflight: dict[tuple[str, str], Future[Any]] = {}
        self._closed = False
        self.wakeup = threading.Event()
        self.stats: dict[str, Any] = {
            "memory_hits": 0,
            "disk_hits": 0,
            "misses": 0,
            "evictions": 0,
            "singleflight_waits": 0,
            "sqlite_seconds": 0.0,
            "peak_hot_bytes": 0,
            "rpc_cache_hits": {},
        }
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path) if path is not None else "")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS entries "
            "(namespace TEXT, key TEXT, value BLOB, PRIMARY KEY(namespace,key))"
        )
        self.db.execute(
            "CREATE TEMP TABLE volatile_entries "
            "(namespace TEXT, key TEXT, value BLOB, PRIMARY KEY(namespace,key))"
        )
        identity = cache_key([self.SCHEMA_VERSION, epoch])
        self.identity = identity
        old = self.db.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
        if old is None or old[0] != identity:
            self.db.execute("DELETE FROM entries")
            self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('identity',?)", (identity,))
        self.db.commit()

    def _call(self, action: Callable[[], Any]) -> Any:
        if threading.get_ident() == self.owner:
            started = time.monotonic()
            try:
                return action()
            finally:
                self.stats["sqlite_seconds"] += time.monotonic() - started
        future: Future[Any] = Future()
        with self._lock:
            if self._closed:
                raise RuntimeError("derived cache closed")
            self._requests.put_nowait((action, future))
            self.wakeup.set()
        return future.result()

    def pump(self) -> None:
        assert threading.get_ident() == self.owner
        for _ in range(64):
            try:
                action, future = self._requests.get_nowait()
            except queue.Empty:
                break
            try:
                future.set_result(self._call(action))
            except BaseException as exc:
                future.set_exception(exc)

    def snapshot(self) -> dict[str, Any]:
        """Nonblocking with respect to the SQLite owner, suitable for heartbeats."""
        with self._lock:
            return dict(
                self.stats,
                rpc_cache_hits=dict(self.stats["rpc_cache_hits"]),
                pending_sqlite=self._requests.qsize(),
                inflight_computations=len(self._inflight),
                hot_bytes=self._bytes,
            )

    def _remember(self, key: tuple[str, str], blob: bytes) -> None:
        with self._lock:
            old = self._hot.pop(key, None)
            self._bytes -= len(old) if old else 0
            if len(blob) <= self.max_bytes:
                self._hot[key] = blob
                self._bytes += len(blob)
            while self._bytes > self.max_bytes:
                _, removed = self._hot.popitem(last=False)
                self._bytes -= len(removed)
                self.stats["evictions"] += 1
            self.stats["peak_hot_bytes"] = max(self.stats["peak_hot_bytes"], self._bytes)

    def get(self, namespace: str, key: str) -> Any:
        rpc = (
            namespace
            if namespace
            in {"symbolInfo", "definition", "declaration", "references", "use_references"}
            else ""
        )
        namespace = self.identity + ":" + namespace
        identity = (namespace, key)
        with self._lock:
            blob = self._hot.get(identity)
            if blob is not None:
                self._hot.move_to_end(identity)
                self.stats["memory_hits"] += 1
                if rpc:
                    hits = self.stats["rpc_cache_hits"]
                    hits[rpc] = int(hits.get(rpc, 0)) + 1
                return json.loads(blob)
        row = self._call(
            lambda: self.db.execute(
                "SELECT value FROM volatile_entries WHERE namespace=? AND key=? UNION ALL "
                "SELECT value FROM entries WHERE namespace=? AND key=? LIMIT 1",
                identity + identity,
            ).fetchone()
        )
        if row is None:
            with self._lock:
                self.stats["misses"] += 1
            return None
        with self._lock:
            self.stats["disk_hits"] += 1
            if rpc:
                hits = self.stats["rpc_cache_hits"]
                hits[rpc] = int(hits.get(rpc, 0)) + 1
        self._remember(identity, row[0])
        return json.loads(row[0])

    def put(self, namespace: str, key: str, value: Any) -> None:
        namespace = self.identity + ":" + namespace
        blob = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
        table = (
            "volatile_entries" if isinstance(value, dict) and value.get("_volatile") else "entries"
        )
        self._call(
            lambda: self.db.execute(
                f"INSERT OR REPLACE INTO {table} VALUES (?,?,?)", (namespace, key, blob)
            )
        )
        self._remember((namespace, key), blob)

    def compute(self, namespace: str, key: str, action: Callable[[], Any]) -> Any:
        identity = (namespace, key)
        with self._lock:
            future = self._inflight.get(identity)
            owner = future is None
            if owner:
                future = Future()
                self._inflight[identity] = future
            else:
                self.stats["singleflight_waits"] += 1
        assert future is not None
        if not owner:
            return future.result()
        try:
            value = self.get(namespace, key)
            if value is None:
                value = action()
                self.put(namespace, key, value)
            future.set_result(value)
            return value
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._inflight.pop(identity, None)

    def checkpoint(self) -> None:
        self._call(self.db.commit)

    def close(self) -> None:
        assert threading.get_ident() == self.owner
        with self._lock:
            self._closed = True
        self.pump()
        self.db.close()
