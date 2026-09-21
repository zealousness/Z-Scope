"""Use-site identity resolution and file-batched declaration evidence."""

from __future__ import annotations

import threading
import functools
import hashlib
import json
import logging
import os
import re
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from itertools import groupby
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Tuple, Dict, TypeVar, cast

from .clang_derived_cache import DerivedCache, cache_key

_F = TypeVar("_F", bound=Callable[..., Any])
logger = logging.getLogger(__name__)


def input_stamp(path: Path) -> tuple[int, int, int, int] | None:
    try:
        stat = path.stat()
        return (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino)
    except OSError:
        return None


def _scope_path(value: str, project_root: Path) -> Path:
    """Normalize an include-graph path into a resolved stampable path."""
    path = Path(str(value or ""))
    if not path.is_absolute():
        path = project_root / path
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def _env_positive_int(name: str, default: int) -> int:
    try:
        value = int(str(os.environ.get(name, "") or default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _prepare_checkpoint(ex: Any) -> None:
    callback = getattr(ex, "_type_prepare_checkpoint", None)
    if callback is not None:
        callback()


def process_rss(pid: int) -> int | None:
    """Current resident bytes without adding a mandatory monitoring dependency."""
    try:
        if os.name != "nt":
            text = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            match = re.search(r"^VmRSS:\s+(\d+)\s+kB", text, re.MULTILINE)
            return int(match.group(1)) * 1024 if match else None
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("faults", wintypes.DWORD),
                ("peak", ctypes.c_size_t),
                ("rss", ctypes.c_size_t),
                ("paged_peak", ctypes.c_size_t),
                ("paged", ctypes.c_size_t),
                ("nonpaged_peak", ctypes.c_size_t),
                ("nonpaged", ctypes.c_size_t),
                ("pagefile", ctypes.c_size_t),
                ("pagefile_peak", ctypes.c_size_t),
            ]

        dll = getattr(ctypes, "WinDLL")
        kernel = dll("kernel32", use_last_error=True)
        api = dll("psapi", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        api.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Counters),
            wintypes.DWORD,
        ]
        handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            return None
        try:
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if api.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return int(counters.rss)
        finally:
            kernel.CloseHandle(handle)
    except (OSError, ValueError, AttributeError):
        pass
    return None


def derived_session(method: _F) -> _F:
    @functools.wraps(method)
    def wrapped(ex: Any, db: Any, *args: Any, **kwargs: Any) -> Any:
        if ex._derived_resolver is not None:
            return method(ex, db, *args, **kwargs)
        identity_started = time.monotonic()
        epoch, reusable, reason = build_identity(ex, db)
        identity_seconds = time.monotonic() - identity_started
        original_epoch = epoch
        original_components = getattr(ex, "_derived_identity_components", {})
        if getattr(ex, "_semantic_epoch", None) != epoch:
            with ex._derived_cache_lock:
                ex._semantic_context_cache = OrderedDict()
            with ex._source_text_cache_lock:
                for name in (
                    "_source_text_cache",
                    "_source_lines_cache",
                    "_masked_source_cache",
                    "_function_pointer_name_cache",
                ):
                    getattr(ex, name).clear()
        ex._semantic_epoch = epoch
        path = getattr(db, "_derived_cache_owner_path", None) or getattr(db, "_db_path", None)
        cache_path = Path(path).parent / "clang_derived_cache.sqlite3" if path is not None else None
        # An incomplete dependency inventory never authorizes cross-process reuse.
        if not reusable:
            import uuid

            epoch = cache_key([epoch, uuid.uuid4().hex])
        cache = DerivedCache(cache_path, epoch=epoch)
        cache.stats["identity_seconds"] = identity_seconds
        resolver = DerivedResolver(ex, cache)
        resolver.scope = method.__name__
        resolver.reusable = reusable
        resolver.identity_reason = reason

        def validate() -> bool:
            started = time.monotonic()
            try:
                resolver.set_phase("source-validation")
                resolver.sources.validate_all(resolver.phase_progress)
                resolver.set_phase("identity-validation")
                current_epoch = build_identity(ex, db)[0]
                if current_epoch == original_epoch:
                    return True
                count, examples = _identity_changes(
                    original_components, getattr(ex, "_derived_identity_components", {})
                )
                resolver.identity_change_reason = f"{count} changed inputs; " + "; ".join(examples)
                cache.stats["identity_changes"] = {"count": count, "examples": examples}
                logger.error("[derived-inputs-changed] %s", resolver.identity_change_reason)
                return False
            finally:
                cache.stats["identity_seconds"] += time.monotonic() - started

        resolver.validate = validate
        ex._derived_resolver = resolver
        with resolver.heartbeat():
            try:
                result = method(ex, db, *args, **kwargs)
                if not resolver.validate():
                    raise RuntimeError(
                        "Source, dependencies or base facts changed during derived rebuild: "
                        + resolver.identity_change_reason
                    )
                return result
            finally:
                resolver.set_phase("cache-close")
                try:
                    cache.pump()
                    cache.close()
                finally:
                    ex._last_resolution_cache_stats = dict(
                        cache.stats,
                        resumable=reusable,
                        identity_reason=reason,
                        sources=resolver.sources.snapshot(),
                    )
                    for name in resolver.index_names:
                        snapshot = getattr(ex, "_last_derived_stats", {}).get(name)
                        if snapshot is not None:
                            snapshot["resolution_cache"] = dict(ex._last_resolution_cache_stats)
                    ex._derived_resolver = None

    return cast(_F, wrapped)


def _identity_changes(before: dict[str, str], after: dict[str, str]) -> tuple[int, list[str]]:
    """Bound log output; expose paths/table names, never source or command contents."""
    count = 0
    examples: list[str] = []
    for key in sorted(before.keys() | after.keys()):
        if before.get(key) == after.get(key):
            continue
        count += 1
        if len(examples) < 8:
            action = "added" if key not in before else "removed" if key not in after else "changed"
            examples.append(f"{action} {key}")
    return count, examples


def build_identity(ex: Any, db: Any) -> tuple[str, bool, str]:
    """Conservatively attest dependencies using full (-MD, not -MMD) depfiles.

    Missing/stale depfiles retain disk spill within the run but invalidate durable
    checkpoints on the next run. Never assume the lexical include graph is complete.
    """
    components: dict[str, str] = {}
    inventory: set[Path] = set()
    receipt = getattr(ex, "_compile_preparation", None)
    if receipt is not None:
        receipt.validate(check_tools=False)
        inventory.update(Path(path) for path in json.loads(receipt.dependencies_json))
        components["context:compile-preparation"] = cache_key(
            [receipt.policy_digest, receipt.original_digest, receipt.effective_digest, receipt.tools_json]
        )
    dependencies_by_source: dict[str, set[Path]] = {}
    # Per-TU attestation: only TUs whose full depfile is fresh and self-consistent
    # may scope completeness-critical decisions (candidate pre-pruning).
    attested_by_source: dict[str, set[Path]] = {}
    command_sources: list[str] = []
    observed: dict[Path, tuple[int, int, int, int] | None] = {}
    complete = bool(ex._server_info)
    reason = "complete_dependency_manifest"
    compilation = Path(ex.compile_commands_dir or ex.project_root) / "compile_commands.json"
    observed[compilation] = input_stamp(compilation)
    components["compilation:" + str(compilation)] = "unreadable"
    try:
        raw = compilation.read_bytes()
        components["compilation:" + str(compilation)] = hashlib.sha256(raw).hexdigest()
        commands = json.loads(raw)
        if not isinstance(commands, list) or not commands:
            raise ValueError("empty compilation database")
        for command in commands:
            _prepare_checkpoint(ex)
            directory = Path(command["directory"])
            args = command.get("arguments")
            source = Path(command["file"])
            source = source if source.is_absolute() else directory / source
            inventory.add(source)
            command_sources.append(str(source.resolve()))
            # Shell strings need platform-specific parsing: do not guess.
            if not isinstance(args, list) or "-MD" not in args or "-MMD" in args:
                complete = False
                continue
            source = source.resolve()
            inventory.add(source)
            source_dependencies: set[Path] = {source}
            depfile = None
            for i, arg in enumerate(args):
                if arg == "-MF" and i + 1 < len(args):
                    depfile = Path(args[i + 1])
                elif str(arg).startswith("-MF") and len(str(arg)) > 3:
                    depfile = Path(str(arg)[3:])
            if depfile is None:
                output = command.get("output")
                if output is None and "-o" in args:
                    output = args[args.index("-o") + 1]
                depfile = Path(output).with_suffix(".d") if output else source.with_suffix(".d")
            depfile = depfile if depfile.is_absolute() else directory / depfile
            compile_stale = compilation.stat().st_mtime_ns > depfile.stat().st_mtime_ns
            if compile_stale:
                complete = False
            deptext = depfile.read_text(encoding="utf-8").replace("\\\n", " ")
            # Split the make target separator, leaving Windows drive colons intact.
            parts = re.split(r":\s", deptext, maxsplit=1)
            if len(parts) != 2:
                raise ValueError("invalid dependency file")
            dependencies = re.findall(r"(?:\\.|[^\s])+", parts[1].split("\n\n", 1)[0])
            found_source = False
            dep_newer = False
            for token in dependencies:
                if token.endswith(":"):
                    break  # -MP phony rules are not dependencies
                clean = re.sub(r"\\([ #\\])", r"\1", token)
                path = Path(clean)
                path = path if path.is_absolute() else directory / path
                inventory.add(path)  # Retain aliases to detect symlink retargeting.
                path = path.resolve()
                if path.stat().st_mtime_ns > depfile.stat().st_mtime_ns:
                    complete = False
                    dep_newer = True
                inventory.add(path)
                source_dependencies.add(path)
                found_source |= path == source.resolve()
            complete &= found_source
            inventory.add(depfile.resolve())
            source_dependencies.add(depfile.resolve())
            dependencies_by_source[str(source.resolve())] = source_dependencies
            if found_source and not compile_stale and not dep_newer:
                attested_by_source[str(source.resolve())] = source_dependencies
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        complete = False
    attested_files = set(inventory)
    inventory.update(getattr(ex, "_derived_source_files", ()))
    # Include source content and row IDs: persisted final rows must never refer
    # to recycled IDs after a base rebuild, even if declarations look identical.
    connection = getattr(db, "_conn", None)
    if connection is not None:
        for table in (
            "functions",
            "global_variables",
            "macro_definitions",
            "type_definitions",
            "include_edges",
            "translation_units",
        ):
            table_digest = hashlib.sha256()
            for ordinal, row in enumerate(
                connection.execute(f"SELECT * FROM {table} ORDER BY rowid")
            ):
                if ordinal % 64 == 0:
                    _prepare_checkpoint(ex)
                table_digest.update(repr(tuple(row)).encode("utf-8"))
                if "file_path" in row.keys():
                    path = Path(str(row["file_path"]))
                    path = (path if path.is_absolute() else ex.project_root / path).resolve()
                    inventory.add(path)
                    if table == "functions" and path not in attested_files:
                        complete = False
                if table == "include_edges":
                    for field in ("source_file", "included_file"):
                        if row[field]:
                            value = Path(str(row[field]))
                            # LSP include facts may retain <header.h> as a name,
                            # not a resolved path. Full depfiles attest those.
                            if (
                                field == "included_file"
                                and row["is_system"]
                                and not value.is_absolute()
                            ):
                                continue
                            inventory.add(value if value.is_absolute() else ex.project_root / value)
            components["base:" + table] = table_digest.hexdigest()
    # Conservative invalidation scopes for TUs without a trusted full depfile:
    # the lexical include graph supplies additional known dependencies, but
    # cannot attest completeness (forced/macro-generated includes may be absent).
    # Durable restart reuse still requires `complete`; consumers validate the
    # files a cached row actually read via receipts, which stays the exact
    # backstop. Best-effort: on failure consumers fall back to the full
    # inventory gate, which is slower but equally correct.
    invalidation_scope_by_source: dict[str, set[Path]] = {}
    try:
        scope_targets = [
            source for source in dict.fromkeys(command_sources) if source not in attested_by_source
        ]
        closures = ex._load_include_closures(db, scope_targets) if scope_targets else {}
        for source_name in scope_targets:
            scope = {Path(source_name)}
            for included in closures.get(source_name) or ():
                scope.add(_scope_path(str(included), ex.project_root))
            invalidation_scope_by_source[source_name] = scope
            inventory.update(scope)
    except Exception:
        invalidation_scope_by_source = {}
    config_parents = {ex.project_root, *ex.project_root.parents}
    for source_path in inventory:
        config_parents.update(source_path.parents)
    for parent in sorted(config_parents):
        config = parent / ".clangd"
        observed[config] = input_stamp(config)
        present = config.is_file()
        components["config:" + str(config)] = "present" if present else "absent"
        if present:
            inventory.add(config)
    user_config = (
        Path(os.environ.get("LOCALAPPDATA", "")) / "clangd/config.yaml"
        if os.name == "nt"
        else Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        / "clangd/config.yaml"
    )
    present = user_config.is_file()
    if present:
        inventory.add(user_config)
    observed[user_config] = input_stamp(user_config)
    components["config:" + str(user_config)] = "present" if present else "absent"
    tool = Path(ex.clangd_path)
    observed[tool] = input_stamp(tool)
    if tool.is_file():
        inventory.add(tool)
    for path in sorted(inventory):
        _prepare_checkpoint(ex)
        key = "file:" + str(path)
        try:
            observed[path] = input_stamp(path)
            file_digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    file_digest.update(chunk)
            components[key] = cache_key([str(path.resolve()), file_digest.hexdigest()])
        except OSError as exc:
            components[key] = f"unreadable:{exc.errno}"
            complete = False
    # Captured once per session; consumers validate just their TU's dependencies.
    # Missing manifests use the entire known inventory and never permit restart reuse.
    ex._derived_input_stamps = observed
    ex._derived_dependencies_by_source = dependencies_by_source
    ex._derived_attested_by_source = attested_by_source
    ex._derived_invalidation_scope_by_source = invalidation_scope_by_source
    components["context:tool-and-environment"] = cache_key(
        [
            "derived-v7",
            str(ex.project_root),
            ex.clangd_path,
            ex._server_info,
            ex._position_encoding,
            {
                k: os.environ.get(k)
                for k in (
                    "PATH",
                    "CPATH",
                    "C_INCLUDE_PATH",
                    "CPLUS_INCLUDE_PATH",
                    "SDKROOT",
                    "INCLUDE",
                )
            },
        ]
    )
    ex._derived_identity_components = components
    if not complete:
        reason = "missing_or_stale_full_dependency_manifest"
    return cache_key(components), complete, reason


class DerivedResolver:
    HEARTBEAT_SECONDS = 30.0

    def __init__(self, extractor: Any, cache: DerivedCache):
        self.ex = extractor
        self.cache = cache
        self.local = threading.local()
        from .clang_source_snapshot import DerivedSourceSnapshots
        self.sources = DerivedSourceSnapshots(extractor, cache, self.local)
        self.scope = ""
        self.identity_change_reason = ""
        self.reusable = False
        self.identity_reason = ""
        self.validate: Any = lambda: True
        self.rpc_metrics: dict[str, dict[str, Any]] = {}
        self._group_count = self._group_sum = self._group_max = 0
        self._memory: dict[str, Any] = {}
        self._memory_time = 0.0
        self._progress_lock = threading.Lock()
        self._active: dict[int, dict[str, Any]] = {}
        self._files_total = self._files_completed = 0
        self._phase = "preparing"
        self._phase_started = time.monotonic()
        self._phase_details: dict[str, Any] = {}
        self.cooperative = False
        # Candidate-probe governance: a super-large same-name candidate group
        # otherwise issues one references RPC per candidate and saturates
        # clangd, which in turn fails exactly the batched use-site bindings
        # that would have avoided the per-candidate fallback. The budget caps
        # one flush group; the breaker pauses probing while transport failures
        # dominate the recent window, then resumes with a halved budget.
        self.probe_budget = _env_positive_int("ZSCOPE_CANDIDATE_PROBE_BUDGET", 128)
        self._effective_probe_budget = self.probe_budget
        self._probe_window: deque[int] = deque(maxlen=100)
        self._probe_lock = threading.Lock()
        self._probe_pause_until = 0.0
        self._probe_pause_trips = 0

    def checkpoint(self) -> None:
        callback = getattr(self.local, "checkpoint", None)
        if callback is not None:
            callback()

    def workload(self, total: int) -> None:
        with self._progress_lock:
            self._files_total = total
            self._files_completed = 0
        self.set_phase("collecting")

    def set_phase(self, phase: str) -> None:
        with self._progress_lock:
            previous = self._phase
            elapsed = time.monotonic() - self._phase_started
            self._phase = phase
            self._phase_started = time.monotonic()
            self._phase_details = {}
        logger.info(
            "[derived-phase] phase=%s previous=%s previous_seconds=%.3f", phase, previous, elapsed
        )

    def phase_progress(self, **values: Any) -> None:
        with self._progress_lock:
            self._phase_details.update(values)
            self._phase_details["checked"] = self._phase_details.get("checked", 0) + 1

    def file_completed(self) -> None:
        with self._progress_lock:
            self._files_completed += 1

    def progress(self, **values: Any) -> None:
        with self._progress_lock:
            active = self._active.get(threading.get_ident())
            if active is not None:
                active.update(values)

    @contextmanager
    def operation(self, method: str, path: Path, line: int) -> Iterator[None]:
        self.progress(method=method, query_file=str(path), line=line, rpc_started=time.monotonic())
        try:
            yield
        finally:
            self.progress(method="", query_file="", rpc_started=None)

    def progress_snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._progress_lock:
            active = [dict(value) for value in self._active.values()]
            result = {
                "files_completed": self._files_completed,
                "files_total": self._files_total,
                "phase": self._phase,
                "phase_seconds": round(now - self._phase_started, 1),
                "phase_progress": dict(self._phase_details),
            }
        for value in active:
            value["elapsed_seconds"] = round(now - value.pop("started"), 1)
            rpc_started = value.pop("rpc_started", None)
            value["operation_seconds"] = round(now - rpc_started, 1) if rpc_started else 0.0
        return dict(result, active=active)

    @contextmanager
    def heartbeat(self) -> Iterator[None]:
        # Independent of the file loop, including its single-worker inline path.
        # This thread only snapshots memory; it must never ask the SQLite owner
        # for work, send LSP requests, or hold a lock while logging.
        stop = threading.Event()

        def report() -> None:
            previous_sent = previous_completed = 0
            while not stop.wait(self.HEARTBEAT_SECONDS):
                try:
                    rpc = self.rpc_snapshot()
                    sent = sum(int(v.get("sent", 0)) for v in rpc.values())
                    completed = sum(int(v.get("count", 0)) for v in rpc.values())
                    logger.info(
                        "[derived-heartbeat] progress=%s rpc_delta(sent=%d completed=%d) "
                        "methods=%s cache=%s sources=%s memory=%s",
                        self.progress_snapshot(),
                        sent - previous_sent,
                        completed - previous_completed,
                        rpc,
                        self.cache.snapshot(),
                        self.sources.snapshot(),
                        self.memory_snapshot(),
                    )
                    previous_sent, previous_completed = sent, completed
                except Exception:
                    logger.exception("Failed to collect derived heartbeat")

        monitor = threading.Thread(target=report, name="ClangDerivedHeartbeat", daemon=True)
        monitor.start()
        try:
            yield
        finally:
            stop.set()
            monitor.join()

    @property
    def index_names(self) -> list[str]:
        if self.scope == "rebuild_function_derived_refs":
            return ["function_symbol_context", "function_type_refs"]
        return [
            (
                "function_symbol_context"
                if self.scope == "rebuild_function_symbol_refs"
                else "function_type_refs"
            )
        ]

    def observe_rpc(
        self, method: str, *, status: str = "", code: Any = None, elapsed: float | None = None
    ) -> None:
        # Called under the extractor transport condition, never over an RPC.
        values = self.rpc_metrics.setdefault(
            method, {"count": 0, "latency_sum_ms": 0.0, "samples": []}
        )
        if elapsed is not None:
            values["count"] += 1
            values["latency_sum_ms"] += elapsed
            values["samples"].append(elapsed)
            del values["samples"][:-256]
        if status:
            values[status] = int(values.get(status, 0)) + 1
        if status == "rpc_error":
            errors = values.setdefault("error_codes", {})
            errors[str(code)] = int(errors.get(str(code), 0)) + 1

    def rpc_snapshot(self) -> dict[str, Any]:
        result = {}
        with self.ex._condition:
            for method, values in self.rpc_metrics.items():
                item = {
                    k: (dict(v) if isinstance(v, dict) else v)
                    for k, v in values.items()
                    if k != "samples"
                }
                samples = sorted(values["samples"])
                item["p95_sample_count"] = len(samples)
                item["average_latency_ms"] = round(
                    values["latency_sum_ms"] / max(1, values["count"]), 3
                )
                item["p95_latency_ms"] = (
                    round(samples[max(0, (len(samples) * 95 + 99) // 100 - 1)], 3)
                    if samples
                    else 0.0
                )
                result[method] = item
        return result

    def group_snapshot(self) -> dict[str, Any]:
        with self.ex._condition:
            return {
                "count": self._group_count,
                "maximum": self._group_max,
                "average": round(self._group_sum / max(1, self._group_count), 3),
            }

    def memory_snapshot(self) -> dict[str, Any]:
        if time.monotonic() - self._memory_time < 5:
            return dict(self._memory)
        self._memory_time = time.monotonic()
        for label, pid in (
            ("python", os.getpid()),
            ("clangd", getattr(self.ex.process, "pid", None)),
        ):
            current = process_rss(pid) if pid else None
            self._memory[label + "_rss_bytes"] = current
            if current is not None:
                key = label + "_sampled_peak_rss_bytes"
                self._memory[key] = max(int(self._memory.get(key, 0)), current)
        return dict(self._memory)

    @contextmanager
    def file(self, path: Path) -> Iterator[dict[str, Any]]:
        self.sources.validate_path(path)
        state: dict[str, Any] = {
            "path": self.canonical_path(path),
            "pending": {},
            "completed": {},
            "binding_sources": {},
            "groups": {},
            "use_identities": {},
            "target_reasons": {},
            "candidate_indexes": {},
            "paths": {},
            "final": False,
            "transient": False,
            "leases": OrderedDict(),
        }
        self.local.state = state
        with self._progress_lock:
            self._active[threading.get_ident()] = {
                "file": str(path),
                "phase": "use-sites",
                "started": time.monotonic(),
            }
        try:
            yield state
            self.progress(phase="source-validation")
            self.sources.validate_used(state)
        finally:
            for leased in state["leases"]:
                self.ex.close_document(Path(leased))
            self.local.state = None
            with self._progress_lock:
                self._active.pop(threading.get_ident(), None)

    @contextmanager
    def lease(self, path: Path) -> Iterator[bool]:
        state = getattr(self.local, "state", None)
        key = self.canonical_path(path)
        if state is None:
            opened = bool(self.ex.open_document(path))
            try:
                yield opened
            finally:
                if opened:
                    self.ex.close_document(path)
            return
        leases = state["leases"]
        if key not in leases:
            if len(leases) >= 4:
                previous = next(item for item in leases if item != state["path"])
                leases.pop(previous)
                self.ex.close_document(Path(previous))
            if not self.ex.open_document(path):
                state["transient"] = True
                yield False
                return
            leases[key] = True
        leases.move_to_end(key)
        yield True

    def _context(self, path: Path) -> str:
        state = getattr(self.local, "state", None)
        if state:
            return str(state["path"])
        return self.canonical_path(path)

    def canonical_path(self, path: Path) -> str:
        return str(self.sources.path(path)["absolute"])

    def index_ready(self) -> bool:
        if self.ex.process is None:
            return True  # injected, synchronous compiler fixtures
        healthy = self.ex.is_healthy() if self.cooperative else False
        with self.ex._condition:
            if (self.cooperative and healthy
                    and not self.ex._has_active_progress_locked()
                    and time.monotonic() - self.ex._last_progress_time >= 5.0):
                # Background collection does not synchronously wait for the
                # whole index. Observe the same idle criterion as wait_for_indexing.
                self.ex._derived_index_ready = True
            return bool(
                getattr(self.ex, "_derived_index_ready", False)
                and not self.ex._has_active_progress_locked()
            )

    def semantic_tokens(self, path: Path) -> Any:
        """Persist successful token RPCs before yielding a function continuation."""
        method = "textDocument/semanticTokens/full"
        key = cache_key([self._context(path), self.canonical_path(path)])

        def compute() -> dict[str, Any]:
            self.ex.get_thread_rpc_outcome(method, clear=True)
            try:
                response = self.ex.get_semantic_tokens(path)
            except Exception:
                response = None
            outcome = self.ex.get_thread_rpc_outcome(method)
            valid = isinstance(response, dict) and isinstance(response.get("data"), list)
            return {"response": response, "_volatile": not valid,
                    "status": outcome.get("status", "unavailable")}

        result = self.cache.compute("semanticTokens", key, compute)
        state = getattr(self.local, "state", None)
        if state is not None and result.get("_volatile"):
            state["transient"] = True
        self.checkpoint()
        return result.get("response")

    def _rpc(
        self, method: str, path: Path, line: int, char: int, stats: dict[str, Any]
    ) -> dict[str, Any]:
        key = cache_key([self._context(path), self.canonical_path(path), line, char])

        def compute() -> dict[str, Any]:
            metric = "symbol_info_requests" if method == "symbolInfo" else method + "_requests"
            stats[metric] = int(stats.get(metric, 0)) + 1
            rpc_method = "textDocument/" + method
            self.ex.get_thread_rpc_outcome(rpc_method, clear=True)
            ready = self.index_ready()
            try:
                # Acquire lazily: candidate-free/local-only files need no extra
                # document open. Retain the use TU through both resolver passes.
                with self.operation(rpc_method, path, line), self.lease(path) as opened:
                    if not opened:
                        return {
                            "items": [],
                            "status": "document_unavailable",
                            "_volatile": True,
                        }
                    if method == "symbolInfo":
                        raw = self.ex.get_symbol_details(path, line - 1, char)
                    elif method == "declaration":
                        raw = self.ex.get_declaration(path, line - 1, char)
                    else:
                        raw = self.ex.get_definition(path, line - 1, char)
                outcome = self.ex.get_thread_rpc_outcome(rpc_method)
                status = str(
                    outcome.get("status") or ("success" if raw is not None else "unavailable")
                )
            except Exception:
                raw, status = None, "rpc_error"
            if status == "timeout" and method == "definition":
                stats["definition_timeouts"] = int(stats.get("definition_timeouts", 0)) + 1
            return {
                "items": (raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []),
                "status": status,
                "_volatile": status not in {"success", "success_nonempty", "success_empty"}
                or (not raw and not (ready and self.index_ready())),
            }

        result = self.cache.compute(method, key, compute)
        state = getattr(self.local, "state", None)
        if state is not None and result.get("_volatile"):
            state["transient"] = True
        self.checkpoint()
        return cast(dict[str, Any], result)

    def location(self, raw: dict[str, Any]) -> tuple[str, int, int] | None:
        uri = raw.get("uri") or raw.get("targetUri")
        rng = raw.get("targetSelectionRange") or raw.get("range") or raw.get("targetRange")
        if not uri or not isinstance(rng, dict) or not isinstance(rng.get("start"), dict):
            return None
        start = rng["start"]
        if not str(uri).startswith("file://"):
            return None
        info = self.sources.path(str(uri), uri=True)
        line, char = int(start.get("line", 0)), int(start.get("character", 0))
        return self.sources.coordinate(info, line, char)

    def unique_locations(self, locations: list[Any]) -> Iterator[dict[str, Any]]:
        """Group URIs and discard duplicate selections before touching source text."""
        grouped: dict[str, dict[tuple[int, int], dict[str, Any]]] = {}
        for raw in locations:
            if not isinstance(raw, dict):
                continue
            uri = str(raw.get("uri") or raw.get("targetUri") or "")
            rng = raw.get("targetSelectionRange") or raw.get("range") or raw.get("targetRange")
            if not uri.startswith("file://") or not isinstance(rng, dict):
                continue
            start = rng.get("start")
            if not isinstance(start, dict):
                continue
            key = (int(start.get("line", 0)), int(start.get("character", 0)))
            grouped.setdefault(uri, {}).setdefault(key, raw)
        for values in grouped.values():
            yield from values.values()

    def normalized_path(self, file: str) -> str:
        state = getattr(self.local, "state", None)
        paths = state["paths"] if state is not None else {}
        if file not in paths:
            paths[file] = self.ex._reference_file_key(self.sources.path(file)["absolute"])
        return cast(str, paths[file])

    def locations(self, locations: list[Any]) -> Iterator[tuple[str, int, int]]:
        for uri, group in groupby(
            self.unique_locations(locations),
            lambda raw: str(raw.get("uri") or raw.get("targetUri")),
        ):
            info = self.sources.path(uri, uri=True)
            # Keep one active file view even if it exceeds the hot LRU budget.
            # Otherwise each coordinate would decode the entire file from SQLite.
            view = self.sources.source_for_path(info)
            for ordinal, raw in enumerate(group):
                if ordinal and ordinal % 64 == 0:
                    self.checkpoint()
                rng = raw.get("targetSelectionRange") or raw.get("range") or raw.get("targetRange")
                assert isinstance(rng, dict)
                start = rng["start"]
                yield self.sources.coordinate(
                    info, int(start.get("line", 0)), int(start.get("character", 0)), view=view
                )

    def candidate_index(self, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        state = getattr(self.local, "state", None)
        indexes = state["candidate_indexes"] if state is not None else {}
        key = id(candidates)
        if key not in indexes:
            by_file: dict[str, list[dict[str, Any]]] = {}
            by_identity = {}
            for candidate in candidates:
                file = self.normalized_path(str(candidate.get("file_path") or ""))
                by_file.setdefault(file, []).append(candidate)
                by_identity[self.ex._candidate_identity(candidate)[:-1]] = candidate
            # Retain the input list so object IDs cannot be recycled within a file.
            indexes[key] = {
                "candidates": candidates,
                "by_file": by_file,
                "by_identity": by_identity,
            }
        return cast(dict[str, Any], indexes[key])

    def remember_identity(self, key: str, candidates: list[dict[str, Any]]) -> None:
        previous = self.cache.get("identity", key) or {}
        declarations = {tuple(value) for value in previous.get("declarations", [])}
        declarations.update(self.ex._candidate_identity(candidate)[:-1] for candidate in candidates)
        self.cache.put("identity", key, {"declarations": sorted(declarations)})

    def match(
        self, candidates: list[dict[str, Any]], locations: list[Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        matches = self.matching_declarations(candidates, locations, context)
        return matches[0] if len(matches) == 1 else None

    def matching_declarations(
        self,
        candidates: list[dict[str, Any]],
        locations: list[Any],
        context: dict[str, Any],
        *,
        selection_only: bool = False,
    ) -> list[dict[str, Any]]:
        matches: dict[tuple[Any, ...], dict[str, Any]] = {}
        index = self.candidate_index(candidates)
        previous_uri, info, in_file = "", {}, []
        view = None
        for raw in self.unique_locations(locations):
            uri = str(raw.get("uri") or raw.get("targetUri"))
            if uri != previous_uri:
                previous_uri, view = uri, None
                info = self.sources.path(uri, uri=True)
                in_file = index["by_file"].get(self.ex._reference_file_key(info["absolute"]), [])
            if not in_file:
                continue
            rng = raw.get("targetSelectionRange") or raw.get("range") or raw.get("targetRange")
            assert isinstance(rng, dict)
            target_line = int(rng["start"].get("line", 0)) + 1
            in_range = [candidate for candidate in in_file
                        if int(candidate.get("line") or candidate.get("start_line") or 0)
                        <= target_line <= max(int(candidate.get("end_line") or 0),
                                             int(candidate.get("line") or candidate.get("start_line") or 0))]
            if not in_range:
                continue
            if view is None:
                view = self.sources.source_for_path(info)
            target_file, line, char = self.sources.coordinate(
                info, target_line - 1, int(rng["start"].get("character", 0)), view=view
            )
            lines = view["lines"]
            for candidate in in_range:
                start = int(candidate.get("line") or candidate.get("start_line") or 0)
                end = max(start, int(candidate.get("end_line") or start))
                if not start <= line <= end:
                    continue
                declaration = self.ex._candidate_declaration_position(candidate, context)
                exact = declaration is not None and (declaration[1], declaration[2]) == (
                    line,
                    char,
                )
                # A compiler selection must never bind to a different member or
                # initializer merely because it is inside an enclosing record.
                name = str(candidate.get("name") or "")
                token = (
                    re.match(r"[A-Za-z_]\w*", lines[line - 1][char:])
                    if lines and 0 < line <= len(lines)
                    else None
                )
                spelled = bool(token and token.group() == name)
                ranged = bool(
                    not selection_only
                    and declaration is None
                    and spelled
                    and start <= line <= end
                    and end >= start > 0
                )
                if exact or ranged:
                    matches[self.ex._candidate_identity(candidate)] = candidate
        return list(matches.values())

    def resolve(
        self,
        candidates: list[dict[str, Any]],
        kind: str,
        path: Path,
        line: int,
        char: int,
        context: dict[str, Any],
        stats: dict[str, Any],
        include_closure: list[str] | None = None,
    ) -> tuple[dict[str, Any] | None, str]:
        self.local.last_binding = ""
        if not candidates:
            return None, "definition_not_indexed"
        state = getattr(self.local, "state", None)
        if state is not None and "include_priority" not in state:
            state["include_priority"] = {
                self.normalized_path(file): i
                for i, file in enumerate(include_closure or [str(path)])
            }
        group_key = (kind, id(candidates))
        cached_group = state["groups"].get(group_key) if state is not None else None
        group = cached_group[0] if cached_group is not None else None
        if group is None:
            group = cache_key([kind, [self.ex._candidate_identity(c) for c in candidates]])
            with self.ex._condition:
                self._group_count += 1
                self._group_sum += len(candidates)
                self._group_max = max(self._group_max, len(candidates))
            if state is not None:
                state["groups"][group_key] = (group, candidates)
        occurrence = (group, line, char)
        if state is not None and state["final"]:
            if occurrence in state["completed"]:
                self.local.last_binding = state["binding_sources"].get(occurrence, "")
                return cast(Tuple[Optional[Dict[str, Any]], str], state["completed"][occurrence])

        can_info = self.ex._symbol_info_supported is not False and (
            self.ex.process is not None
            or "get_symbol_info" in self.ex.__dict__
            or "get_symbol_details" in self.ex.__dict__
        )
        details = self._rpc("symbolInfo", path, line, char, stats) if can_info else {"items": []}
        items = [d for d in details["items"] if isinstance(d, dict)]
        identities_info = {str(d.get("usr") or d.get("id") or "") for d in items}
        identity_key = None
        if len(identities_info) == 1 and next(iter(identities_info)):
            identity_key = cache_key([self._context(path), kind, next(iter(identities_info))])
            cached = self.cache.get("identity", identity_key)
            if cached is not None:
                if cached.get("outside_scope_group") == group:
                    return None, "definition_outside_scope"
                indexed = self.candidate_index(candidates)["by_identity"]
                mapped = [
                    indexed[tuple(value)]
                    for value in cached.get("declarations", [])
                    if tuple(value) in indexed
                ]
                if mapped:
                    stats["usr_resolved"] = int(stats.get("usr_resolved", 0)) + 1
                    self.local.last_binding = "identity"
                    return self.ex._canonical_candidate_representative(mapped, kind), ""
            locations = [
                item[k]
                for item in items
                for k in ("definitionRange", "declarationRange")
                if item.get(k)
            ]
            matched = self.match(candidates, locations, context)
            if matched is not None:
                self.remember_identity(identity_key, [matched])
                stats["usr_resolved"] = int(stats.get("usr_resolved", 0)) + 1
                self.local.last_binding = "identity"
                return matched, ""

        definitions = self._rpc("definition", path, line, char, stats)
        matched = self.match(candidates, definitions["items"], context)
        if matched is not None:
            if identity_key:
                self.remember_identity(identity_key, [matched])
            self.local.last_binding = "definition"
            return matched, ""
        if len(identities_info) > 1:
            return None, "symbol_info_ambiguous"
        # Older clangd symbolInfo responses omit locations. Declaration lookup
        # uses the current TU's AST; it does not require parsing candidate files.
        declarations: dict[str, Any] = {"items": []}
        if self.ex._declaration_supported is not False and (
            self.ex.process is not None or "get_declaration" in self.ex.__dict__
        ):
            declarations = self._rpc("declaration", path, line, char, stats)
            matched = self.match(candidates, declarations["items"], context)
            if matched is not None:
                if identity_key:
                    self.remember_identity(identity_key, [matched])
                self.local.last_binding = "declaration"
                return matched, ""
        if state is None:
            return self.references(candidates, kind, path, line, char, context, stats)
        state["pending"][occurrence] = (candidates, kind, path, line, char, context, stats)
        state["use_identities"][occurrence] = next(iter(identities_info)) if identity_key else ""
        target_locations = [
            loc
            for raw in definitions["items"] + declarations["items"]
            if isinstance(raw, dict)
            if (loc := self.location(raw)) is not None
        ]
        state["target_reasons"][occurrence] = (
            "definition_outside_scope"
            if target_locations and all(Path(loc[0]).is_absolute() for loc in target_locations)
            else (
                "definition_not_indexed"
                if target_locations
                else "usr_unmapped" if identity_key else "definition_unresolved"
            )
        )
        return None, "pending_reference"

    def references(
        self,
        candidates: list[dict[str, Any]],
        kind: str,
        path: Path,
        line: int,
        char: int,
        context: dict[str, Any],
        stats: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str]:
        matched = self.ex._resolve_candidate_by_references(
            candidates,
            kind=kind,
            source_path=path,
            line=line,
            character=char,
            semantic_context=context,
            stats=stats,
        )
        if matched is not None:
            stats["references_resolved"] = int(stats.get("references_resolved", 0)) + 1
            self.local.last_binding = "references"
            return matched, ""
        return None, "definition_unresolved"

    def use_reference_declarations(
        self,
        candidates: list[dict[str, Any]],
        path: Path,
        line: int,
        char: int,
        context: dict[str, Any],
        stats: dict[str, Any],
        usr: str,
    ) -> list[dict[str, Any]]:
        # A single compiler identity is required: locations from an ambiguous
        # use must never be interpreted as redeclarations of one symbol. Reuse
        # only within this TU; headers may mean different things in another TU.
        key = cache_key([self._context(path), self.canonical_path(path), usr])

        def compute() -> dict[str, Any]:
            method = "textDocument/references"
            self.ex.get_thread_rpc_outcome(method, clear=True)
            ready = self.index_ready()
            try:
                with self.operation(method, path, line), self.lease(path) as opened:
                    if not opened:
                        return {"items": [], "_volatile": True}
                    stats["references_requests"] = int(stats.get("references_requests", 0)) + 1
                    raw = self.ex.get_references(path, line - 1, char, include_declaration=True)
                    outcome = self.ex.get_thread_rpc_outcome(method)
            except Exception:
                raw, outcome = None, {"status": "rpc_error"}
            success = isinstance(raw, list) and outcome.get("status", "success").startswith(
                "success"
            )
            return {
                "items": raw if success else [],
                "complete": success and ready and self.index_ready() and len(raw or []) < 1000,
                "_volatile": not success or not (ready and self.index_ready()),
            }

        result = self.cache.compute("use_references", key, compute)
        self.checkpoint()
        state = getattr(self.local, "state", None)
        if state is not None and result.get("_volatile"):
            state["transient"] = True
        # Even a capped response can positively identify a declaration of the
        # known use-site USR. Absence never eliminates a candidate. Only exact
        # declaration selections qualify; ordinary uses inside a range do not.
        return self.matching_declarations(candidates, result["items"], context, selection_only=True)

    def reference_locations(
        self,
        candidate: dict[str, Any],
        kind: str,
        context: dict[str, Any],
        stats: dict[str, Any],
        canonical: Any,
    ) -> set[tuple[str, int, int]]:
        declaration = self.ex._candidate_declaration_position(candidate, context)
        key = cache_key(
            [
                self._context(declaration[0]) if declaration else "",
                kind,
                canonical,
                list(self.ex._candidate_identity(candidate)[:-1]),
            ]
        )

        def compute() -> dict[str, Any]:
            if declaration is None:
                return {
                    "locations": [],
                    "complete": False,
                    "capped": False,
                    "status": "no_declaration",
                    "_volatile": True,
                }
            path, line, char = declaration
            self.ex.get_thread_rpc_outcome("textDocument/references", clear=True)
            ready = self.index_ready()
            try:
                with (
                    self.operation("textDocument/references", path, line),
                    self.lease(path) as opened,
                ):
                    if not opened:
                        return {
                            "locations": [],
                            "complete": False,
                            "capped": False,
                            "status": "document_unavailable",
                            "_volatile": True,
                        }
                    stats["references_requests"] = int(stats.get("references_requests", 0)) + 1
                    raw = self.ex.get_references(path, line - 1, char, include_declaration=False)
                    outcome = self.ex.get_thread_rpc_outcome("textDocument/references")
            except Exception:
                raw, outcome = None, {"status": "rpc_error"}
            success = isinstance(raw, list) and outcome.get("status", "success").startswith(
                "success"
            )
            locations = list(self.locations(raw or []))
            ready = ready and self.index_ready()
            capped = bool(success and len(raw or []) >= 1000)
            return {
                "locations": locations,
                "complete": success and ready and not capped,
                "capped": capped,
                "status": str(
                    outcome.get("status") or ("success" if success else "rpc_error")
                ),
                "_volatile": not success or not ready,
            }

        result = self.cache.compute("references", key, compute)
        self.checkpoint()
        context["_last_reference_complete"] = bool(result["complete"])
        self._record_probe_outcome(result)
        state = getattr(self.local, "state", None)
        if state is not None and not result["complete"] and not result.get("capped"):
            # A capped response is permanent for this session (retrying cannot
            # shrink a >=1000-location reference set), so it must not poison
            # the whole function into a transient retry. Transport failures
            # may genuinely recover on a later attempt and stay transient.
            state["transient"] = True
        return {
            (self.ex._reference_file_key(loc[0]), loc[1], loc[2]) for loc in result["locations"]
        }

    def _record_probe_outcome(self, result: dict[str, Any]) -> None:
        """Track candidate-probe health; trip the breaker on failure storms."""
        status = str(result.get("status") or "")
        failed = status in {"rpc_error", "timeout", "unavailable", "document_unavailable"}
        with self._probe_lock:
            self._probe_window.append(0 if failed else 1)
            window = self._probe_window
            now = time.monotonic()
            if len(window) >= 20 and now >= self._probe_pause_until and sum(window) * 2 < len(window):
                self._probe_pause_until = now + 10.0
                self._probe_pause_trips += 1
                self._effective_probe_budget = max(8, self._effective_probe_budget // 2)
                logger.warning(
                    "[derived-resolver] candidate probe breaker open trips=%d "
                    "failure_rate=%.2f effective_budget=%d",
                    self._probe_pause_trips,
                    1.0 - (sum(window) / len(window)),
                    self._effective_probe_budget,
                )
            elif (
                len(window) == window.maxlen
                and all(window)
                and self._effective_probe_budget < self.probe_budget
            ):
                self._effective_probe_budget = min(
                    self.probe_budget, self._effective_probe_budget * 2
                )

    def flush(self, state: dict[str, Any]) -> None:
        # All unresolved uses are collected before querying declarations. Group
        # results and the disk cache are shared across files, unlike the old LRU.
        self.progress(function=None, function_start_line=None)
        grouped: dict[str, list[Any]] = {}
        for occurrence, args in state["pending"].items():
            grouped.setdefault(occurrence[0], []).append((occurrence, args))
        for uses in grouped.values():
            self.checkpoint()
            candidates, kind, path, _, _, context, stats = uses[0][1]
            priority = state.get("include_priority", {})
            # Visibility changes search order only. Keep every candidate, and
            # query neighboring declarations together to reuse document leases.
            candidates = sorted(
                candidates,
                key=lambda c: (
                    priority.get(
                        self.normalized_path(str(c.get("file_path") or "")), len(priority)
                    ),
                    self.normalized_path(str(c.get("file_path") or "")),
                    int(c.get("line") or c.get("start_line") or 0),
                ),
            )
            # Attested-dependency scoping (P4): with a fresh, compiler-proven
            # dependency manifest for this TU, an internal-linkage candidate
            # declared outside the TU's compilation cannot be referenced from
            # it, and candidates declared outside it rank behind visible ones.
            # External-linkage candidates are never dropped: a forward
            # declaration inside the TU can still bind to a definition whose
            # file the manifest never lists.
            attested = getattr(self.ex, "_derived_attested_by_source", None) or {}
            tu_deps = attested.get(str(state["path"]))
            if tu_deps is not None:
                tu_path_keys = {
                    self.ex._reference_file_key(str(dep)) for dep in tu_deps
                } | {self.ex._reference_file_key(str(state["path"]))}
                outside_flags = [
                    (
                        candidate,
                        self.normalized_path(str(candidate.get("file_path") or ""))
                        not in tu_path_keys,
                    )
                    for candidate in candidates
                ]
                prune_count = sum(
                    1 for candidate, outside in outside_flags if outside and candidate.get("is_static")
                )
                if prune_count:
                    candidates = [
                        candidate
                        for candidate, outside in outside_flags
                        if not (outside and candidate.get("is_static"))
                    ]
                    stats["probe_pruned_candidates"] = (
                        int(stats.get("probe_pruned_candidates") or 0) + prune_count
                    )
                    outside_flags = [
                        (candidate, outside)
                        for candidate, outside in outside_flags
                        if not (outside and candidate.get("is_static"))
                    ]
                if any(outside for _, outside in outside_flags) and not all(
                    outside for _, outside in outside_flags
                ):
                    # Probe visible candidates first so a truncated budget
                    # spends itself on plausible bindings. Stable sort keeps
                    # the include-priority order inside each class.
                    rank = {id(candidate): outside for candidate, outside in outside_flags}
                    candidates.sort(key=lambda candidate: rank[id(candidate)])
            self.progress(phase="use-references", group_size=len(candidates), candidate_done=0)
            # Resolve from the already parsed use TU before opening any candidate
            # document. Never prefetch every same-name declaration's symbolInfo.
            by_usr: dict[str, list[dict[str, Any]]] = {}
            remaining = []
            for occurrence, args in uses:
                usr = state["use_identities"].get(occurrence, "")
                if usr and usr not in by_usr:
                    by_usr[usr] = self.use_reference_declarations(
                        candidates, path, args[3], args[4], context, stats, usr
                    )
                    if by_usr[usr]:
                        self.remember_identity(
                            cache_key([self._context(path), kind, usr]), by_usr[usr]
                        )
                members = by_usr.get(usr, [])
                if members:
                    state["completed"][occurrence] = (
                        self.ex._canonical_candidate_representative(members, kind),
                        "",
                    )
                    state["binding_sources"][occurrence] = "identity"
                    stats["usr_resolved"] = int(stats.get("usr_resolved", 0)) + 1
                else:
                    remaining.append((occurrence, args))
            uses = remaining
            if not uses:
                continue
            wanted = {
                (
                    self.ex._reference_file_key(self.ex._project_relative_path(args[2])),
                    args[3],
                    args[4],
                ): occurrence
                for occurrence, args in uses
            }
            matches: dict[Any, list[dict[str, Any]]] = {}
            complete = True
            # Probe governance applies to the cooperative background collector,
            # where one saturated group starves every waiter. Rebuild sessions
            # keep the unbounded all-candidates semantics their consumers and
            # tests rely on.
            governed = bool(self.cooperative)
            paused = governed and time.monotonic() < self._probe_pause_until
            budget = max(1, int(self._effective_probe_budget))
            probed = 0
            budget_exhausted = paused
            if paused:
                stats["probe_paused_groups"] = int(stats.get("probe_paused_groups") or 0) + 1
            else:
                self.progress(phase="declaration-references", candidate_done=0)
            for ordinal, candidate in enumerate(candidates, 1):
                if governed and probed >= budget:
                    # Unprobed candidates leave uniqueness unproven for every
                    # use in this group: record the truncation explicitly
                    # instead of pretending the evidence is complete, and let
                    # the group resolve as unresolved rather than transient.
                    budget_exhausted = True
                    stats["probe_budget_exhausted"] = (
                        int(stats.get("probe_budget_exhausted") or 0) + 1
                    )
                    break
                canonical = ("candidate", kind, self.ex._candidate_identity(candidate))
                locations = self.reference_locations(candidate, kind, context, stats, canonical)
                probed += 1
                complete &= bool(context.get("_last_reference_complete"))
                for coordinate in locations.intersection(wanted):
                    matches.setdefault(wanted[coordinate], []).append(candidate)
                self.progress(candidate_done=ordinal)
                if ordinal % 64 == 0:
                    self.checkpoint()
            for occurrence, _args in uses:
                values = matches.get(occurrence, [])
                occurrence_complete = complete and not budget_exhausted
                usr = state["use_identities"].get(occurrence, "")
                # USRs are only needed for positive evidence: distinguish two
                # matches from two declarations of the same entity. Failed or
                # capped candidate queries still cannot prove uniqueness.
                groups: dict[Any, list[dict[str, Any]]] = {}
                if len(values) > 1 or (values and usr):
                    self.progress(phase="matched-declaration-identities")
                    for candidate in values:
                        canonical = self.ex._candidate_canonical_identity(
                            candidate, kind=kind, semantic_context=context, stats=stats
                        )
                        groups.setdefault(canonical, []).append(candidate)
                    known = [
                        members
                        for canonical, members in groups.items()
                        if usr and canonical[0] in {"usr", "symbol_id"} and canonical[2] == usr
                    ]
                    if len(known) == 1:
                        self.remember_identity(
                            cache_key([self._context(path), kind, usr]), known[0]
                        )
                        state["completed"][occurrence] = (
                            self.ex._canonical_candidate_representative(known[0], kind),
                            "",
                        )
                        state["binding_sources"][occurrence] = "identity"
                        stats["usr_resolved"] = int(stats.get("usr_resolved", 0)) + 1
                        continue
                    values = [
                        self.ex._canonical_candidate_representative(m, kind)
                        for m in groups.values()
                    ]
                    if usr and any(c[0] in {"usr", "symbol_id"} for c in groups):
                        # Conflicting compiler identities are not repaired by
                        # an otherwise unique reverse-reference hit.
                        occurrence_complete = False
                if occurrence_complete and len(values) == 1:
                    state["completed"][occurrence] = (values[0], "")
                    state["binding_sources"][occurrence] = "references"
                    stats["references_resolved"] = int(stats.get("references_resolved", 0)) + 1
                else:
                    state["completed"][occurrence] = (
                        None,
                        (
                            "reference_ambiguous"
                            if len(values) > 1
                            else (
                                "reference_probe_paused"
                                if paused
                                else "reference_budget_exhausted"
                                if budget_exhausted
                                else "reference_incomplete"
                                if not occurrence_complete
                                else state["target_reasons"].get(
                                    occurrence, "definition_unresolved"
                                )
                            )
                        ),
                    )
        self.progress(phase="materialize", method="")
        state["final"] = True
