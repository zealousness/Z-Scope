"""Session-scoped source views; filesystem validation happens at task boundaries.

The metadata/source LRUs and the broker's serialized LRU share one byte
allowance. Cold views spill to the broker's TEMP table; checkpoints contain
small validation receipts, never source bodies or per-coordinate entries.
"""

from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Callable, cast, Optional, List
from urllib.parse import urlparse
from urllib.request import url2pathname


class SourceInputsChanged(RuntimeError):
    def __init__(self, reason: str):
        super().__init__("Inputs changed: " + reason)


def _bytes(value: Any) -> int:
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(_bytes(k) + _bytes(v) for k, v in value.items())
    elif isinstance(value, (list, tuple)):
        size += sum(_bytes(v) for v in value)
    return size


class DerivedSourceSnapshots:
    def __init__(self, ex: Any, cache: Any, local: threading.local):
        self.ex, self.cache, self.local = ex, cache, local
        self.budget = cache.max_bytes // 2
        cache.max_bytes -= self.budget
        self.hot: OrderedDict[tuple[str, str], tuple[dict[str, Any], int]] = OrderedDict()
        self.source_hot: OrderedDict[tuple[str, str], tuple[dict[str, Any], int]] = OrderedDict()
        self.metadata_used = self.source_used = 0
        self.used = 0
        self.lock = threading.RLock()
        self.inflight: dict[tuple[str, str], Future[dict[str, Any]]] = {}
        self.stats: dict[str, Any] = dict(
            path_hits=0,
            source_hits=0,
            coordinate_hits=0,
            stamp_hits=0,
            coordinates=0,
            resolve_count=0,
            resolve_seconds=0.0,
            stat_count=0,
            stat_seconds=0.0,
            source_reads=0,
            evictions=0,
            hot_bytes=0,
            peak_hot_bytes=0,
            validation_checks=0,
            validation_seconds=0.0,
            receipt_batches=0,
        )

    def metric(self, name: str, value: Any = 1) -> None:
        with self.lock:
            self.stats[name] = self.stats.get(name, 0) + value

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.stats)

    def _resolve(self, path: Path) -> str:
        started = time.monotonic()
        try:
            return str(path.resolve())
        finally:
            self.metric("resolve_count")
            self.metric("resolve_seconds", time.monotonic() - started)

    def _stamp(self, path: Path) -> list[int] | None:
        started = time.monotonic()
        try:
            stat = path.stat()
            return [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino, stat.st_dev]
        except OSError:
            return None
        finally:
            self.metric("stat_count")
            self.metric("stat_seconds", time.monotonic() - started)

    def _get(self, kind: str, key: str, compute: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        identity = (kind, key)
        bucket = self.source_hot if kind == "source" else self.hot
        weight_name = "source_used" if kind == "source" else "metadata_used"
        with self.lock:
            cached = bucket.get(identity)
            if cached is not None:
                bucket.move_to_end(identity)
                self.stats[kind + "_hits"] += 1
                return cached[0]
            future = self.inflight.get(identity)
            owner = future is None
            if owner:
                future = Future()
                self.inflight[identity] = future
        assert future is not None
        if not owner:
            return cast(dict[str, Any], self.cache.wait_for(future))
        try:

            def volatile() -> dict[str, Any]:
                value = dict(compute(), _volatile=True)
                if kind == "source":
                    # Validation must never retrieve/decode the full source
                    # merely to compare its small version/digest receipt.
                    self.cache.put(
                        "source_view_stamp", key, {k: v for k, v in value.items() if k != "lines"}
                    )
                return value

            value = cast(dict[str, Any], self.cache.compute("source_view_" + kind, key, volatile))
            size = _bytes(value) + _bytes(identity)
            with self.lock:
                # Large source files and streams of coordinates must not evict
                # the small path/version working set for all active workers.
                limit = self.budget // 2
                weight = getattr(self, weight_name)
                if size <= limit:
                    bucket[identity] = (value, size)
                    weight += size
                while weight > limit:
                    _, (_, removed) = bucket.popitem(last=False)
                    weight -= removed
                    self.stats["evictions"] += 1
                setattr(self, weight_name, weight)
                self.used = self.metadata_used + self.source_used
                self.stats["hot_bytes"] = self.used
                self.stats["peak_hot_bytes"] = max(self.stats["peak_hot_bytes"], self.used)
            future.set_result(value)
            return value
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self.lock:
                self.inflight.pop(identity, None)

    def _track(self, kind: str, key: str) -> None:
        state = getattr(self.local, "state", None)
        if state is not None:
            state.setdefault("source_views", set()).add((kind, key))

    def path(self, value: str | Path, *, uri: bool = False) -> dict[str, Any]:
        raw = str(value)
        path = Path(url2pathname(urlparse(raw).path)) if uri else Path(raw)
        if not path.is_absolute():
            path = self.ex.project_root / path
        key = str(path)
        self._track("path", key)

        def compute() -> dict[str, Any]:
            # Keep '..' until realpath: collapsing it first changes symlink semantics.
            absolute = self._resolve(path)
            try:
                project = Path(absolute).relative_to(self.ex.project_root).as_posix()
            except ValueError:
                project = Path(absolute).as_posix()
            return dict(alias=str(path), absolute=absolute, project=project)

        return self._get("path", key, compute)

    def lines(self, value: str | Path) -> list[str] | None:
        info = self.path(value)
        return self.lines_for_path(info)

    def lines_for_path(self, info: dict[str, Any]) -> list[str] | None:
        return cast(Optional[List[str]], self.source_for_path(info)["lines"])

    def source_for_path(self, info: dict[str, Any]) -> dict[str, Any]:
        absolute = info["absolute"]
        self._track("source", absolute)

        def compute() -> dict[str, Any]:
            path = Path(absolute)
            before = self._stamp(path)
            try:
                raw = path.read_bytes()
                self.metric("source_reads")
            except OSError:
                if before is not None:
                    raise SourceInputsChanged("source_unavailable: " + absolute)
                return dict(path=absolute, stamp=None, lines=None, digest="")
            if self._stamp(path) != before:
                raise SourceInputsChanged("source_changed_during_read: " + absolute)
            return dict(
                path=absolute,
                stamp=before,
                digest=hashlib.sha256(raw).hexdigest(),
                # Match Path.read_text's universal-newline behavior.
                lines=raw.decode("utf-8", errors="ignore")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .splitlines(True),
            )

        return self._get("source", absolute, compute)

    def version_key(self, path: Path) -> tuple[str, int, int] | None:
        info = self.path(path)
        self._track("source", info["absolute"])
        source = self._get(
            "stamp",
            info["absolute"],
            lambda: {k: v for k, v in self.source_for_path(info).items() if k != "lines"},
        )
        stamp = source["stamp"]
        return (info["absolute"], stamp[1], stamp[0]) if stamp is not None else None

    def coordinate(
        self, info: dict[str, Any], line: int, char: int, *, view: dict[str, Any] | None = None
    ) -> tuple[str, int, int]:
        self.metric("coordinates")
        self._track("source", info["absolute"])
        # ASCII conversion is already O(1), and non-ASCII conversion only scans
        # the selected line. A separate entry per coordinate costs more than
        # recomputation and used to evict every useful source/path entry.
        lines = view["lines"] if view is not None else self.lines_for_path(info)
        offset = char
        if lines and 0 <= line < len(lines):
            offset = self.ex._lsp_offset_to_python_in_text(lines[line], char)
        return info["project"], line + 1, offset

    def _validate(self, kind: str, value: dict[str, Any], *, content: bool = False) -> None:
        self.metric("validation_checks")
        if kind == "path":
            if self._resolve(Path(value["alias"])) != value["absolute"]:
                raise SourceInputsChanged("source_path_changed: " + value["alias"])
        elif kind == "source":
            path = Path(value["path"])
            if self._stamp(path) != value["stamp"]:
                raise SourceInputsChanged("source_version_changed: " + str(path))
            # Windows ctime may be creation time, so size/mtime/ctime alone
            # cannot prove freshness after an editor restores the timestamp.
            if (content or os.name == "nt") and value["stamp"] is not None:
                if hashlib.sha256(path.read_bytes()).hexdigest() != value["digest"]:
                    raise SourceInputsChanged("source_content_changed: " + str(path))

    def validate_used(self, state: dict[str, Any]) -> None:
        started = time.monotonic()
        try:
            for receipt in self.receipts(state):
                self._validate(receipt["kind"], receipt["value"])
        finally:
            self.metric("validation_seconds", time.monotonic() - started)

    def receipts(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        result = []
        views = state.get("source_views", ())
        for kind in ("path", "source"):
            keys = sorted(key for view_kind, key in views if view_kind == kind)
            if not keys:
                continue
            self.metric("receipt_batches")
            namespace = "source_view_" + ("stamp" if kind == "source" else kind)
            values = self.cache.get_many(namespace, keys)
            for key in keys:
                value = values.get(key)
                if value is None:
                    raise SourceInputsChanged("missing_source_receipt: " + key)
                result.append(
                    dict(
                        kind=kind,
                        value={k: v for k, v in value.items() if k not in {"lines", "_volatile"}},
                    )
                )
        return result

    def validate_receipts(self, receipts: list[dict[str, Any]]) -> None:
        for receipt in receipts:
            # Retain restored inputs in this session as well: a later publish
            # must revalidate them even when no new RPC visited the location.
            value = receipt["value"]
            if receipt["kind"] == "path":
                self.path(value["alias"])
            elif receipt["kind"] == "source":
                self.lines(value["path"])
            self._validate(receipt["kind"], receipt["value"])

    def validate_all(self, progress: Callable[..., None] | None = None) -> None:
        for kind in ("path", "source"):

            def validate(value: dict[str, Any]) -> None:
                if progress is not None:
                    progress(
                        validation_kind=kind,
                        validation_file=value.get("alias") or value.get("path"),
                    )
                self._validate(kind, value, content=True)

            self.cache.visit_volatile(
                "source_view_" + ("stamp" if kind == "source" else kind), validate
            )

    def validate_path(self, value: str | Path) -> None:
        info = self.path(value)
        self._validate("path", info)
        source = self.cache.get("source_view_stamp", info["absolute"])
        if source is not None:
            self._validate("source", source)
