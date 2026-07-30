"""Snapshot storage, cache management, and index-name schema migration."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional, cast

from ..common.utils import compute_code_hash, compute_semantic_fingerprint
from .policy import (
    DETERMINISTIC_SNAPSHOT_KINDS,
    is_current_deterministic_snapshot_shape,
)

logger = logging.getLogger(__name__)

_SQLITE_PRAGMA_LOCK = threading.Lock()
# Keep the readable component short enough for legacy Windows MAX_PATH once
# snapshot directories and the atomic-write ".tmp" suffix are included.
_INDEX_FILENAME_PREFIX_LIMIT = 96
_SYMBOL_CONTEXT_ARRAY_FIELDS = (
    "referenced_globals",
    "referenced_macros",
)
_SYMBOL_CONTEXT_OPTIONAL_FIELDS = (
    "referenced_globals_truncation",
    "referenced_macros_truncation",
    "project_callees_truncation",
    "external_callees_truncation",
    "unresolved_callees_truncation",
)
_GLOBAL_STORAGE_CLASSES = {
    "static",
    "extern",
    "thread_local",
    "global",
    "unknown",
}
_GLOBAL_QUALIFIER_ORDER = (
    "const",
    "volatile",
    "atomic",
)


def _clone_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clone_json_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_clone_json_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_clone_json_value(item) for item in value)
    return value


def _clone_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return {str(key): _clone_json_value(value) for key, value in snapshot.items()}


def _ensure_snapshot_symbol_context(snapshot: Dict[str, Any]) -> bool:
    changed = False
    for field in _SYMBOL_CONTEXT_ARRAY_FIELDS:
        if not isinstance(snapshot.get(field), list):
            snapshot[field] = []
            changed = True
    for item in snapshot["referenced_globals"]:
        if not isinstance(item, dict):
            continue
        storage_class = str(item.get("storage_class") or "unknown")
        if storage_class not in _GLOBAL_STORAGE_CLASSES:
            item["storage_class"] = "unknown"
            changed = True
        qualifiers = item.get("qualifiers")
        if isinstance(qualifiers, str):
            raw_qualifiers = [part.strip() for part in qualifiers.split(",")]
        elif isinstance(qualifiers, (list, tuple, set)):
            raw_qualifiers = [str(part).strip() for part in qualifiers]
        else:
            raw_qualifiers = []
        selected = {value for value in raw_qualifiers if value}
        normalized = [
            qualifier
            for qualifier in _GLOBAL_QUALIFIER_ORDER
            if qualifier in selected
        ]
        if qualifiers != normalized:
            item["qualifiers"] = normalized
            changed = True
    return changed


def _canonical_symbol_records(value: Any) -> list[Any]:
    records = list(value) if isinstance(value, list) else []
    return sorted(
        records,
        key=lambda item: json.dumps(
            item,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
    )


def _canonical_callee_records(
    value: Any,
    *,
    identity_field: str,
    include_project_flags: bool = False,
    include_summary: bool = False,
) -> list[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        identity = str(item.get(identity_field) or "").strip()
        if not identity:
            continue
        entry = groups.setdefault(
            identity,
            {
                identity_field: identity,
                "callee_signature": "",
                "direct_callsite_lines": set(),
                "indirect_callsites": [],
                "is_static": False,
                "callee_summary": "unknown",
            },
        )
        raw_lines = item.get("direct_callsite_lines")
        if raw_lines is None:
            raw_lines = item.get("callsite_lines")
        if isinstance(raw_lines, (list, tuple, set)):
            entry["direct_callsite_lines"].update(
                int(line)
                for line in raw_lines
                if isinstance(line, int) and not isinstance(line, bool) and line > 0
            )
        entry["indirect_callsites"].extend(
            _clone_json_value(callsite)
            for callsite in list(item.get("indirect_callsites") or [])
            if isinstance(callsite, dict)
        )
        signature = str(item.get("callee_signature") or "").strip()
        if signature:
            entry["callee_signature"] = signature
        if include_project_flags:
            entry["is_static"] = bool(item.get("is_static"))
        if include_summary:
            candidate_summary = str(item.get("callee_summary") or "").strip()
            if candidate_summary and candidate_summary != "unknown":
                entry["callee_summary"] = candidate_summary

    result = []
    for identity, entry in sorted(groups.items()):
        record = {
            identity_field: identity,
            "direct_callsite_lines": sorted(entry["direct_callsite_lines"]),
            "indirect_callsites": _canonical_symbol_records(entry["indirect_callsites"]),
        }
        if entry["callee_signature"]:
            record["callee_signature"] = entry["callee_signature"]
        if include_project_flags:
            record["is_static"] = entry["is_static"]
        if include_summary:
            record["callee_summary"] = entry["callee_summary"]
        result.append(record)
    return result


def compute_symbol_context_hash(payload: Dict[str, Any]) -> str:
    """Hash the program-extracted callee, global, and macro dependencies."""

    context: Dict[str, Any] = {
        field: _canonical_symbol_records(payload.get(field))
        for field in _SYMBOL_CONTEXT_ARRAY_FIELDS
    }
    context["project_callees"] = _canonical_callee_records(
        payload.get("project_callees"),
        identity_field="callee_index_name",
        include_project_flags=True,
    )
    context["external_callees"] = _canonical_callee_records(
        payload.get("external_callees"),
        identity_field="callee_name",
    )
    if payload.get("unresolved_callees"):
        context["unresolved_callees"] = _canonical_callee_records(
            payload.get("unresolved_callees"),
            identity_field="callee_name",
        )
    for field in _SYMBOL_CONTEXT_OPTIONAL_FIELDS:
        if field in payload:
            context[field] = payload[field]
    encoded = json.dumps(
        context,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def compute_callee_summary_hash(payload: Dict[str, Any]) -> str:
    """Hash only canonical project-callee identities and passthrough summaries."""

    summaries: Dict[str, str] = {}
    raw_callees = payload.get("project_callees")
    for item in raw_callees if isinstance(raw_callees, list) else []:
        if not isinstance(item, dict):
            continue
        index_name = str(item.get("callee_index_name") or "").strip()
        if not index_name:
            continue
        summary = str(item.get("callee_summary") or "").strip() or "unknown"
        existing = summaries.get(index_name)
        if existing is None or (existing == "unknown" and summary != "unknown"):
            summaries[index_name] = summary
    encoded = json.dumps(
        [
            {"callee_index_name": index_name, "callee_summary": summaries[index_name]}
            for index_name in sorted(summaries)
        ],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalized_type_definition(value: Any) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def compute_type_context_hash(payload: Dict[str, Any]) -> str:
    """Hash direct type identities/references using internal definition digests."""
    resolved: Dict[str, Dict[str, Any]] = {}
    raw_types = payload.get("referenced_types")
    for item in raw_types if isinstance(raw_types, list) else []:
        if not isinstance(item, dict):
            continue
        identity = str(item.get("type_index_name") or "").strip()
        if not identity:
            continue
        definition = _normalized_type_definition(item.get("full_definition"))
        resolved[identity] = {
            "type_index_name": identity,
            "kind": str(item.get("kind") or ""),
            "definition_hash": hashlib.sha256(definition.encode("utf-8")).hexdigest(),
            "reference_kinds": sorted(
                {str(value) for value in item.get("reference_kinds", [])}
            ),
            "reference_lines": sorted(
                {
                    int(value)
                    for value in item.get("reference_lines", [])
                    if isinstance(value, int) and not isinstance(value, bool) and value > 0
                }
            ),
        }

    unresolved_records = []
    raw_unresolved = payload.get("unresolved_referenced_types")
    for item in raw_unresolved if isinstance(raw_unresolved, list) else []:
        if not isinstance(item, dict):
            continue
        unresolved_records.append(
            {
                "name": str(item.get("name") or ""),
                "reason": str(item.get("reason") or ""),
                "reference_kinds": sorted(
                    {str(value) for value in item.get("reference_kinds", [])}
                ),
                "reference_lines": sorted(
                    {
                        int(value)
                        for value in item.get("reference_lines", [])
                        if isinstance(value, int)
                        and not isinstance(value, bool)
                        and value > 0
                    }
                ),
            }
        )
    unresolved_records.sort(
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
    )
    projection: Dict[str, Any] = {
        "referenced_types": [resolved[key] for key in sorted(resolved)],
        "unresolved_referenced_types": unresolved_records,
    }
    if "referenced_types_truncation" in payload:
        projection["referenced_types_truncation"] = payload[
            "referenced_types_truncation"
        ]
    encoded = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class SnapshotLockManager:
    """Serialize snapshot builds by canonical function index name."""

    def __init__(self) -> None:
        self._global_lock = threading.Lock()
        self._func_locks: Dict[str, threading.Lock] = {}
        self._modeling_status: Dict[str, str] = {}

    @staticmethod
    def _lock_key(index_name: str) -> str:
        key = str(index_name or "").strip()
        if not key:
            raise ValueError("snapshot lock requires a non-empty index_name")
        return key

    def acquire(self, index_name: str, timeout: float = 120.0) -> str:
        """Return acquired, done, or timeout for one canonical function."""

        lock_key = self._lock_key(index_name)
        with self._global_lock:
            if lock_key not in self._func_locks:
                self._func_locks[lock_key] = threading.Lock()
                self._modeling_status[lock_key] = "idle"
            if self._modeling_status[lock_key] == "done":
                return "done"

        lock = self._func_locks[lock_key]
        if not lock.acquire(timeout=timeout):
            return "timeout"
        with self._global_lock:
            if self._modeling_status[lock_key] == "done":
                lock.release()
                return "done"
            self._modeling_status[lock_key] = "modeling"
        return "acquired"

    def acquire_refresh(self, index_name: str, timeout: float = 120.0) -> str:
        """Acquire the per-index lock even when a completed snapshot already exists."""

        lock_key = self._lock_key(index_name)
        with self._global_lock:
            if lock_key not in self._func_locks:
                self._func_locks[lock_key] = threading.Lock()
                self._modeling_status[lock_key] = "idle"
            lock = self._func_locks[lock_key]
        if not lock.acquire(timeout=timeout):
            return "timeout"
        with self._global_lock:
            self._modeling_status[lock_key] = "modeling"
        return "acquired"

    def release(self, index_name: str, success: bool = True) -> None:
        lock_key = self._lock_key(index_name)
        with self._global_lock:
            self._modeling_status[lock_key] = "done" if success else "failed"
        lock = self._func_locks.get(lock_key)
        if lock:
            try:
                lock.release()
            except RuntimeError:
                pass

    def invalidate(self, index_name: str) -> None:
        lock_key = self._lock_key(index_name)
        with self._global_lock:
            if lock_key in self._modeling_status:
                self._modeling_status[lock_key] = "failed"


class SnapshotStore:
    """Persist snapshots and final reports using index_name as the only key."""

    DEFAULT_CACHE_MAX_BYTES = 512 * 1024 * 1024

    def __init__(
        self,
        snapshot_dir: Path,
        *,
        cache_max_bytes: int = DEFAULT_CACHE_MAX_BYTES,
    ):
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.snapshot_dir / "snapshots.db"
        self.lock_manager = SnapshotLockManager()
        self._cache_max_bytes = max(0, int(cache_max_bytes))
        self._cache_bytes = 0
        self._cache: "OrderedDict[tuple[str, str], bytes]" = OrderedDict()
        self._cache_lock = threading.RLock()
        self._init_db()

    @staticmethod
    def _encoded_index_name(index_name: str) -> str:
        raw = str(index_name or "").strip()
        if not raw:
            raise ValueError("snapshot storage requires a non-empty index_name")
        readable = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
        readable = readable[:_INDEX_FILENAME_PREFIX_LIMIT] or "snapshot"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"{readable}-{digest}"

    @classmethod
    def _snapshot_filename(cls, index_name: str) -> str:
        return f"{cls._encoded_index_name(index_name)}.json"

    @classmethod
    def _final_report_filename(cls, index_name: str) -> str:
        return f"{cls._encoded_index_name(index_name)}_final.json"

    def _cached_snapshot(self, index_name: str) -> Optional[Dict[str, Any]]:
        return self._cached_json_value(("snapshot", index_name))

    def _cache_snapshot(self, index_name: str, snapshot: Dict[str, Any]) -> None:
        self._cache_json_value(("snapshot", index_name), snapshot)

    def _invalidate_snapshot_cache(self, index_name: str) -> None:
        self._invalidate_cache_key(("snapshot", index_name))

    def _cached_final_report(self, index_name: str) -> Optional[Dict[str, Any]]:
        return self._cached_json_value(("report", index_name))

    def _cache_final_report(self, index_name: str, report: Dict[str, Any]) -> None:
        self._cache_json_value(("report", index_name), report)

    def _invalidate_final_report_cache(self, index_name: str) -> None:
        self._invalidate_cache_key(("report", index_name))

    def _cached_json_value(
        self,
        key: tuple[str, str],
    ) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            encoded = self._cache.get(key)
            if encoded is None:
                return None
            self._cache.move_to_end(key)
        # Cached values are immutable JSON bytes.  Parsing gives each caller an
        # isolated object without retaining duplicate deep-copied object graphs.
        try:
            value = json.loads(encoded)
        except Exception:
            self._invalidate_cache_key(key)
            logger.exception(
                "[snapshot-store] in-memory cache decode failed kind=%s index_name=%s",
                key[0],
                key[1],
            )
            return None
        return value if isinstance(value, dict) else None

    def _cache_json_value(
        self,
        key: tuple[str, str],
        value: Dict[str, Any],
    ) -> None:
        if self._cache_max_bytes <= 0:
            return
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > self._cache_max_bytes:
            self._invalidate_cache_key(key)
            return
        with self._cache_lock:
            previous = self._cache.pop(key, None)
            if previous is not None:
                self._cache_bytes -= len(previous)
            self._cache[key] = encoded
            self._cache_bytes += len(encoded)
            while self._cache and self._cache_bytes > self._cache_max_bytes:
                _evicted_key, evicted = self._cache.popitem(last=False)
                self._cache_bytes -= len(evicted)

    def _invalidate_cache_key(self, key: tuple[str, str]) -> None:
        with self._cache_lock:
            encoded = self._cache.pop(key, None)
            if encoded is not None:
                self._cache_bytes -= len(encoded)

    def cache_stats(self) -> Dict[str, int]:
        """Return bounded-cache telemetry for diagnostics and regression tests."""

        with self._cache_lock:
            return {
                "entries": len(self._cache),
                "bytes": self._cache_bytes,
                "max_bytes": self._cache_max_bytes,
            }

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @staticmethod
    def _create_schema(conn: sqlite3.Connection, table_name: str = "snapshots") -> None:
        conn.execute(
            f"""
            CREATE TABLE {table_name} (
                index_name TEXT PRIMARY KEY,
                func_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                semantic_hash TEXT NOT NULL,
                symbol_context_hash TEXT NOT NULL,
                callee_summary_hash TEXT NOT NULL,
                type_context_hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                snapshot_file TEXT NOT NULL,
                final_report_file TEXT
            )
            """
        )

    @staticmethod
    def _create_validation_cache_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS validation_cache (
                cache_key TEXT PRIMARY KEY,
                protocol TEXT NOT NULL,
                candidate_schema_version TEXT NOT NULL,
                environment_fingerprint TEXT NOT NULL,
                result_json TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            with _SQLITE_PRAGMA_LOCK:
                conn.execute("PRAGMA journal_mode=WAL")
            self._create_validation_cache_schema(conn)
            conn.commit()
            table_exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='snapshots'"
            ).fetchone()
            if not table_exists:
                self._create_schema(conn)
                conn.commit()
                return

            columns = {row[1]: row for row in conn.execute("PRAGMA table_info(snapshots)")}
            if "index_name" in columns and int(columns["index_name"][5] or 0) == 1:
                self._ensure_symbol_context_column(conn, columns)
                self._ensure_callee_summary_column(conn, columns)
                self._ensure_type_context_column(conn, columns)
                self._audit_storage_filename_collisions(conn)
                return
            self._migrate_to_index_schema(conn)
            self._audit_storage_filename_collisions(conn)
        finally:
            conn.close()

    def _audit_storage_filename_collisions(self, conn: sqlite3.Connection) -> None:
        """Invalidate ambiguous legacy report links without deleting their files.

        Snapshot payloads carry ``index_name`` and are therefore validated when
        loaded. Final reports do not carry a storage identity, so a filename
        referenced by multiple rows cannot be attributed safely. Clearing only
        those database links forces regeneration while preserving every legacy
        JSON file for manual recovery.
        """

        snapshot_collisions = [
            str(row[0])
            for row in conn.execute(
                "SELECT snapshot_file FROM snapshots "
                "WHERE snapshot_file <> '' "
                "GROUP BY snapshot_file HAVING COUNT(*) > 1"
            )
        ]
        for snapshot_file in snapshot_collisions:
            index_names = [
                str(row[0])
                for row in conn.execute(
                    "SELECT index_name FROM snapshots "
                    "WHERE snapshot_file = ? ORDER BY index_name",
                    (snapshot_file,),
                )
            ]
            logger.error(
                "[snapshot-store] shared legacy snapshot file detected "
                "snapshot_file=%s index_names=%s "
                "reason=snapshot_filename_collision",
                snapshot_file,
                index_names,
            )

        final_collisions = [
            str(row[0])
            for row in conn.execute(
                "SELECT final_report_file FROM snapshots "
                "WHERE final_report_file IS NOT NULL AND final_report_file <> '' "
                "GROUP BY final_report_file HAVING COUNT(*) > 1"
            )
        ]
        if not final_collisions:
            return
        for final_report_file in final_collisions:
            index_names = [
                str(row[0])
                for row in conn.execute(
                    "SELECT index_name FROM snapshots "
                    "WHERE final_report_file = ? ORDER BY index_name",
                    (final_report_file,),
                )
            ]
            logger.error(
                "[snapshot-store] invalidating ambiguous legacy final report links "
                "final_report_file=%s index_names=%s "
                "reason=final_report_filename_collision",
                final_report_file,
                index_names,
            )
            conn.execute(
                "UPDATE snapshots SET final_report_file = NULL "
                "WHERE final_report_file = ?",
                (final_report_file,),
            )
        conn.commit()

    def _ensure_symbol_context_column(
        self,
        conn: sqlite3.Connection,
        columns: Dict[str, Any],
    ) -> None:
        if "symbol_context_hash" in columns:
            return

        empty_hash = compute_symbol_context_hash({})
        conn.execute(
            "ALTER TABLE snapshots ADD COLUMN symbol_context_hash "
            f"TEXT NOT NULL DEFAULT '{empty_hash}'"
        )
        rows = conn.execute(
            "SELECT index_name, snapshot_file FROM snapshots"
        ).fetchall()
        migrated = 0
        failed = 0
        for index_name, snapshot_file in rows:
            snapshot_path = self.snapshot_dir / str(snapshot_file or "")
            try:
                snapshot = cast(
                    Dict[str, Any],
                    json.loads(snapshot_path.read_text(encoding="utf-8")),
                )
                changed = _ensure_snapshot_symbol_context(snapshot)
                if changed:
                    self._write_json_atomic(snapshot_path, snapshot)
                symbol_hash = compute_symbol_context_hash(snapshot)
                conn.execute(
                    "UPDATE snapshots SET symbol_context_hash = ? WHERE index_name = ?",
                    (symbol_hash, str(index_name)),
                )
                migrated += 1
            except Exception as exc:
                failed += 1
                logger.warning(
                    "[snapshot-migration] symbol context backfill failed "
                    "index_name=%s snapshot_file=%s "
                    "reason=symbol_context_backfill_failed error=%s",
                    index_name,
                    snapshot_file,
                    exc,
                )
        conn.commit()
        logger.info(
            "[snapshot-migration] symbol context column completed "
            "total=%d migrated=%d failed=%d",
            len(rows),
            migrated,
            failed,
        )

    def _ensure_callee_summary_column(
        self,
        conn: sqlite3.Connection,
        columns: Dict[str, Any],
    ) -> None:
        if "callee_summary_hash" in columns:
            return

        empty_hash = compute_callee_summary_hash({})
        conn.execute(
            "ALTER TABLE snapshots ADD COLUMN callee_summary_hash "
            f"TEXT NOT NULL DEFAULT '{empty_hash}'"
        )
        rows = conn.execute(
            "SELECT index_name, snapshot_file FROM snapshots"
        ).fetchall()
        migrated = 0
        failed = 0
        for index_name, snapshot_file in rows:
            snapshot_path = self.snapshot_dir / str(snapshot_file or "")
            try:
                snapshot = cast(
                    Dict[str, Any],
                    json.loads(snapshot_path.read_text(encoding="utf-8")),
                )
                conn.execute(
                    "UPDATE snapshots SET symbol_context_hash = ?, "
                    "callee_summary_hash = ? WHERE index_name = ?",
                    (
                        compute_symbol_context_hash(snapshot),
                        compute_callee_summary_hash(snapshot),
                        str(index_name),
                    ),
                )
                migrated += 1
            except Exception as exc:
                failed += 1
                logger.warning(
                    "[snapshot-migration] callee summary backfill failed "
                    "index_name=%s snapshot_file=%s "
                    "reason=callee_summary_backfill_failed error=%s",
                    index_name,
                    snapshot_file,
                    exc,
                )
        conn.commit()
        logger.info(
            "[snapshot-migration] callee summary column completed "
            "total=%d migrated=%d failed=%d",
            len(rows),
            migrated,
            failed,
        )

    def _ensure_type_context_column(
        self,
        conn: sqlite3.Connection,
        columns: Dict[str, Any],
    ) -> None:
        if "type_context_hash" in columns:
            return
        empty_hash = compute_type_context_hash({"referenced_types": []})
        conn.execute(
            "ALTER TABLE snapshots ADD COLUMN type_context_hash "
            f"TEXT NOT NULL DEFAULT '{empty_hash}'"
        )
        conn.commit()
        logger.info(
            "[snapshot-migration] type context column completed "
            "default=canonical_empty_type_context"
        )

    def _legacy_table_name(self, conn: sqlite3.Connection) -> str:
        base = "snapshots_legacy"
        candidate = base
        suffix = 1
        while conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (candidate,),
        ).fetchone():
            candidate = f"{base}_{suffix}"
            suffix += 1
        return candidate

    @staticmethod
    def _legacy_index_name(snapshot: Dict[str, Any], row: sqlite3.Row) -> str:
        existing = str(snapshot.get("index_name") or "").strip()
        if existing:
            return existing
        row_keys = set(row.keys())
        func_name = str(
            snapshot.get("func_name")
            or (row["func_name"] if "func_name" in row_keys else "")
            or ""
        ).strip()
        file_path = str(
            snapshot.get("file_path")
            or (row["file_path"] if "file_path" in row_keys else "")
            or ""
        ).strip()
        start_line = int(snapshot.get("start_line") or 0)
        end_line = int(snapshot.get("end_line") or 0)
        if not func_name or not file_path or start_line <= 0 or end_line < start_line:
            return ""
        return f"{func_name}@{file_path}:{start_line}-{end_line}"

    def _migrate_to_index_schema(self, conn: sqlite3.Connection) -> None:
        previous_row_factory = conn.row_factory
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute("SELECT * FROM snapshots"))
        conn.row_factory = previous_row_factory
        created_files: list[Path] = []
        migrated: list[tuple[Any, ...]] = []
        seen: set[str] = set()
        failed = 0
        collisions = 0
        logger.info("[snapshot-migration] start total=%d", len(rows))

        try:
            for row in rows:
                snapshot_file = str(row["snapshot_file"] or "")
                snapshot_path = self.snapshot_dir / snapshot_file
                if not snapshot_path.exists():
                    failed += 1
                    logger.warning(
                        "[snapshot-migration] snapshot file missing snapshot_file=%s "
                        "reason=migration_snapshot_file_missing",
                        snapshot_file,
                    )
                    continue
                try:
                    snapshot = cast(
                        Dict[str, Any],
                        json.loads(snapshot_path.read_text(encoding="utf-8")),
                    )
                except Exception as exc:
                    failed += 1
                    logger.warning(
                        "[snapshot-migration] snapshot unreadable snapshot_file=%s "
                        "reason=migration_snapshot_unreadable error=%s",
                        snapshot_file,
                        exc,
                    )
                    continue

                index_name = self._legacy_index_name(snapshot, row)
                if not index_name:
                    failed += 1
                    logger.warning(
                        "[snapshot-migration] identity incomplete snapshot_file=%s "
                        "reason=migration_identity_incomplete",
                        snapshot_file,
                    )
                    continue
                if index_name in seen:
                    collisions += 1
                    logger.error(
                        "[snapshot-migration] index collision index_name=%s snapshot_file=%s "
                        "reason=migration_index_collision",
                        index_name,
                        snapshot_file,
                    )
                    continue
                seen.add(index_name)

                snapshot["index_name"] = index_name
                _ensure_snapshot_symbol_context(snapshot)
                row_keys = set(row.keys())
                func_name = str(
                    snapshot.get("func_name")
                    or (row["func_name"] if "func_name" in row_keys else "")
                    or ""
                )
                file_path = str(
                    snapshot.get("file_path")
                    or (row["file_path"] if "file_path" in row_keys else "")
                    or ""
                )
                start_line = int(snapshot.get("start_line") or 0)
                end_line = int(snapshot.get("end_line") or 0)
                new_snapshot_file = self._snapshot_filename(index_name)
                new_snapshot_path = self.snapshot_dir / new_snapshot_file
                self._write_json_atomic(new_snapshot_path, snapshot)
                created_files.append(new_snapshot_path)

                final_report_file = str(row["final_report_file"] or "") if "final_report_file" in row.keys() else ""
                new_final_file: Optional[str] = None
                if final_report_file:
                    old_final_path = self.snapshot_dir / final_report_file
                    if old_final_path.exists():
                        report = json.loads(old_final_path.read_text(encoding="utf-8"))
                        new_final_file = self._final_report_filename(index_name)
                        new_final_path = self.snapshot_dir / new_final_file
                        self._write_json_atomic(new_final_path, report)
                        created_files.append(new_final_path)
                    else:
                        logger.warning(
                            "[snapshot-migration] final report file missing index_name=%s file=%s "
                            "reason=migration_final_report_file_missing",
                            index_name,
                            final_report_file,
                        )

                migrated.append(
                    (
                        index_name,
                        func_name,
                        file_path,
                        start_line,
                        end_line,
                        str(row["code_hash"] or ""),
                        str(row["semantic_hash"] or ""),
                        compute_symbol_context_hash(snapshot),
                        compute_callee_summary_hash(snapshot),
                        compute_type_context_hash(snapshot),
                        new_snapshot_file,
                        new_final_file,
                    )
                )

            if failed or collisions:
                raise RuntimeError(
                    f"snapshot migration failed: failed={failed}, collisions={collisions}"
                )

            conn.execute("BEGIN IMMEDIATE")
            self._create_schema(conn, "snapshots_v5")
            conn.executemany(
                """
                INSERT INTO snapshots_v5 (
                    index_name, func_name, file_path, start_line, end_line,
                    code_hash, semantic_hash, symbol_context_hash, callee_summary_hash,
                    type_context_hash, snapshot_file, final_report_file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                migrated,
            )
            legacy_table = self._legacy_table_name(conn)
            conn.execute(f"ALTER TABLE snapshots RENAME TO {legacy_table}")
            conn.execute("ALTER TABLE snapshots_v5 RENAME TO snapshots")
            conn.commit()
            logger.info(
                "[snapshot-migration] completed total=%d migrated=%d skipped=0 failed=0 collisions=0 legacy_table=%s",
                len(rows),
                len(migrated),
                legacy_table,
            )
        except Exception:
            conn.rollback()
            for path in created_files:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            logger.exception(
                "[snapshot-migration] failed total=%d migrated=%d failed=%d collisions=%d "
                "reason=snapshot_migration_failed",
                len(rows),
                len(migrated),
                failed,
                collisions,
            )
            raise

    @staticmethod
    def _write_json_atomic(path: Path, payload: Any) -> None:
        temp_path = path.with_suffix(path.suffix + ".tmp")
        with open(temp_path, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, indent=2, ensure_ascii=False)
        temp_path.replace(path)

    def save_snapshot(
        self,
        index_name: str,
        snapshot: Dict[str, Any],
        code: str,
        dependency_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload_index = str(snapshot.get("index_name") or "").strip()
        index_name = str(index_name or "").strip()
        if not index_name or payload_index != index_name:
            logger.error(
                "[snapshot-store] index mismatch argument=%s payload=%s "
                "reason=snapshot_index_mismatch",
                index_name,
                payload_index,
            )
            raise ValueError("snapshot index_name does not match save argument")

        func_name = str(snapshot.get("func_name") or "").strip()
        file_path = str(snapshot.get("file_path") or "").strip()
        start_line = int(snapshot.get("start_line") or 0)
        end_line = int(snapshot.get("end_line") or 0)
        if not func_name or not file_path or start_line <= 0 or end_line < start_line:
            logger.error(
                "[snapshot-store] identity incomplete index_name=%s reason=snapshot_identity_incomplete",
                index_name,
            )
            raise ValueError("snapshot identity fields are incomplete")
        invalid_symbol_fields = [
            field
            for field in _SYMBOL_CONTEXT_ARRAY_FIELDS
            if not isinstance(snapshot.get(field), list)
        ]
        if invalid_symbol_fields:
            logger.error(
                "[snapshot-store] symbol context incomplete index_name=%s missing=%s "
                "reason=snapshot_symbol_context_incomplete",
                index_name,
                invalid_symbol_fields,
            )
            raise ValueError("snapshot symbol context fields are incomplete")
        if not isinstance(snapshot.get("referenced_types"), list):
            logger.error(
                "[snapshot-store] type context incomplete index_name=%s "
                "reason=snapshot_type_context_incomplete",
                index_name,
            )
            raise ValueError("snapshot referenced_types field is incomplete")

        try:
            snapshot_file = self._snapshot_filename(index_name)
            snapshot_path = self.snapshot_dir / snapshot_file
            self._write_json_atomic(snapshot_path, snapshot)
            code_hash = compute_code_hash(code)
            semantic_hash = compute_semantic_fingerprint(code)
            symbol_context_hash = compute_symbol_context_hash(
                dependency_context if dependency_context is not None else snapshot
            )
            callee_summary_hash = compute_callee_summary_hash(
                dependency_context if dependency_context is not None else snapshot
            )
            type_context_hash = compute_type_context_hash(
                dependency_context if dependency_context is not None else snapshot
            )

            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO snapshots (
                        index_name, func_name, file_path, start_line, end_line,
                        code_hash, semantic_hash, symbol_context_hash, callee_summary_hash,
                        type_context_hash, snapshot_file, final_report_file
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    ON CONFLICT(index_name) DO UPDATE SET
                        func_name=excluded.func_name,
                        file_path=excluded.file_path,
                        start_line=excluded.start_line,
                        end_line=excluded.end_line,
                        code_hash=excluded.code_hash,
                        semantic_hash=excluded.semantic_hash,
                        symbol_context_hash=excluded.symbol_context_hash,
                        callee_summary_hash=excluded.callee_summary_hash,
                        type_context_hash=excluded.type_context_hash,
                        timestamp=CURRENT_TIMESTAMP,
                        snapshot_file=excluded.snapshot_file,
                        final_report_file=NULL
                    """,
                    (
                        index_name,
                        func_name,
                        file_path,
                        start_line,
                        end_line,
                        code_hash,
                        semantic_hash,
                        symbol_context_hash,
                        callee_summary_hash,
                        type_context_hash,
                        snapshot_file,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            logger.exception(
                "[snapshot-store] save failed index_name=%s reason=snapshot_save_failed",
                index_name,
            )
            raise
        self._invalidate_snapshot_cache(index_name)
        self._invalidate_final_report_cache(index_name)
        self._cache_snapshot(index_name, snapshot)
        logger.info(
            "[snapshot-store] saved index_name=%s snapshot_file=%s",
            index_name,
            snapshot_file,
        )

    def save_final_report(self, index_name: str, final_report: Dict[str, Any]) -> None:
        index_name = str(index_name or "").strip()
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT snapshot_file FROM snapshots WHERE index_name = ?",
                    (index_name,),
                ).fetchone()
                if not row:
                    logger.warning(
                        "[snapshot-store] final report has no snapshot index_name=%s "
                        "reason=final_report_snapshot_missing",
                        index_name,
                    )
                    return
                final_file = self._final_report_filename(index_name)
                self._write_json_atomic(self.snapshot_dir / final_file, final_report)
                conn.execute(
                    "UPDATE snapshots SET final_report_file = ? WHERE index_name = ?",
                    (final_file, index_name),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            logger.exception(
                "[snapshot-store] final report save failed index_name=%s "
                "reason=final_report_save_failed",
                index_name,
            )
            raise
        self._invalidate_final_report_cache(index_name)
        self._cache_final_report(index_name, final_report)
        logger.info(
            "[snapshot-store] saved final report index_name=%s final_report_file=%s",
            index_name,
            final_file,
        )

    def save_validation_result(
        self,
        cache_key: str,
        result: Dict[str, Any],
        *,
        protocol: str,
        candidate_schema_version: str,
        environment_fingerprint: str,
        max_entries: int = 8192,
    ) -> None:
        """Persist one successful contextual Validator response."""

        if not cache_key or not isinstance(result, dict):
            return
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO validation_cache (
                    cache_key, protocol, candidate_schema_version,
                    environment_fingerprint, result_json
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    protocol=excluded.protocol,
                    candidate_schema_version=excluded.candidate_schema_version,
                    environment_fingerprint=excluded.environment_fingerprint,
                    result_json=excluded.result_json,
                    timestamp=CURRENT_TIMESTAMP
                """,
                (
                    cache_key,
                    protocol,
                    candidate_schema_version,
                    environment_fingerprint,
                    encoded,
                ),
            )
            if max_entries > 0:
                conn.execute(
                    """
                    DELETE FROM validation_cache
                    WHERE cache_key IN (
                        SELECT cache_key FROM validation_cache
                        ORDER BY timestamp DESC, cache_key DESC
                        LIMIT -1 OFFSET ?
                    )
                    """,
                    (int(max_entries),),
                )
            conn.commit()
        finally:
            conn.close()

    def load_validation_result(
        self,
        cache_key: str,
        *,
        protocol: str,
        candidate_schema_version: str,
        environment_fingerprint: str,
    ) -> Optional[Dict[str, Any]]:
        """Load only an exactly compatible v3 validation result."""

        if not cache_key:
            return None
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT result_json FROM validation_cache
                WHERE cache_key = ?
                  AND protocol = ?
                  AND candidate_schema_version = ?
                  AND environment_fingerprint = ?
                """,
                (
                    cache_key,
                    protocol,
                    candidate_schema_version,
                    environment_fingerprint,
                ),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        try:
            value = json.loads(str(row[0]))
        except (TypeError, ValueError, json.JSONDecodeError):
            logger.exception(
                "[snapshot-store] validation cache decode failed cache_key=%s",
                cache_key,
            )
            return None
        return value if isinstance(value, dict) else None

    def load_snapshot(self, index_name: str) -> Optional[Dict[str, Any]]:
        index_name = str(index_name or "").strip()
        cached = self._cached_snapshot(index_name)
        if cached is not None:
            return cached
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT snapshot_file FROM snapshots WHERE index_name = ?",
                (index_name,),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            logger.debug("[snapshot-store] snapshot miss index_name=%s", index_name)
            return None
        snapshot_path = self.snapshot_dir / str(row[0])
        if not snapshot_path.exists():
            logger.warning(
                "[snapshot-store] snapshot file missing index_name=%s snapshot_file=%s "
                "reason=snapshot_file_missing",
                index_name,
                row[0],
            )
            return None
        try:
            snapshot = cast(
                Dict[str, Any],
                json.loads(snapshot_path.read_text(encoding="utf-8")),
            )
        except Exception:
            logger.exception(
                "[snapshot-store] snapshot read failed index_name=%s snapshot_file=%s "
                "reason=snapshot_read_failed",
                index_name,
                row[0],
            )
            return None
        if str(snapshot.get("index_name") or "") != index_name:
            logger.error(
                "[snapshot-store] persisted index mismatch requested=%s payload=%s "
                "reason=persisted_snapshot_index_mismatch",
                index_name,
                snapshot.get("index_name"),
            )
            return None
        _ensure_snapshot_symbol_context(snapshot)
        self._cache_snapshot(index_name, snapshot)
        return snapshot

    def load_final_report(self, index_name: str) -> Optional[Dict[str, Any]]:
        index_name = str(index_name or "").strip()
        cached = self._cached_final_report(index_name)
        if cached is not None:
            return cached
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT snapshot_file, final_report_file "
                "FROM snapshots WHERE index_name = ?",
                (index_name,),
            ).fetchone()
            reference_count = (
                conn.execute(
                    "SELECT COUNT(*) FROM snapshots WHERE final_report_file = ?",
                    (str(row[1]),),
                ).fetchone()[0]
                if row and row[1]
                else 0
            )
        finally:
            conn.close()
        if not row or not row[1]:
            logger.debug("[snapshot-store] final report miss index_name=%s", index_name)
            return None
        if int(reference_count) != 1:
            logger.error(
                "[snapshot-store] ambiguous final report reference index_name=%s "
                "final_report_file=%s references=%s "
                "reason=final_report_filename_collision",
                index_name,
                row[1],
                reference_count,
            )
            return None
        if self.load_snapshot(index_name) is None:
            logger.error(
                "[snapshot-store] final report owner snapshot is invalid index_name=%s "
                "reason=final_report_snapshot_identity_invalid",
                index_name,
            )
            return None
        final_path = self.snapshot_dir / str(row[1])
        if not final_path.exists():
            logger.warning(
                "[snapshot-store] final report file missing index_name=%s final_report_file=%s "
                "reason=final_report_file_missing",
                index_name,
                row[1],
            )
            return None
        try:
            report = cast(
                Dict[str, Any],
                json.loads(final_path.read_text(encoding="utf-8")),
            )
        except Exception:
            logger.exception(
                "[snapshot-store] final report read failed index_name=%s final_report_file=%s "
                "reason=final_report_read_failed",
                index_name,
                row[1],
            )
            return None
        self._cache_final_report(index_name, report)
        return report

    def get_fingerprints(self, index_name: str) -> Optional[Dict[str, str]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT code_hash, semantic_hash, symbol_context_hash, callee_summary_hash, "
                "type_context_hash "
                "FROM snapshots WHERE index_name = ?",
                (index_name,),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        return {
            "code_hash": str(row[0]),
            "semantic_hash": str(row[1]),
            "symbol_context_hash": str(row[2]),
            "callee_summary_hash": str(row[3]),
            "type_context_hash": str(row[4]),
        }

    def reconcile_project_callee_summaries(
        self,
        index_name: str,
        current_symbol_context: Dict[str, Any],
    ) -> str:
        """Refresh program-owned project callee summaries without invoking an LLM.

        Returns one of refreshed, unchanged, missing, llm_refresh_required, timeout,
        or failed.
        """

        index_name = str(index_name or "").strip()
        project_callees = current_symbol_context.get("project_callees")
        if not index_name or not isinstance(project_callees, list):
            return "failed"
        if any(
            not isinstance(item, dict) or "is_macro" in item
            for item in project_callees
        ):
            return "llm_refresh_required"

        lock_status = self.lock_manager.acquire_refresh(index_name)
        if lock_status == "timeout":
            return "timeout"

        success = False
        try:
            snapshot = self.load_snapshot(index_name)
            fingerprints = self.get_fingerprints(index_name)
            if snapshot is None or fingerprints is None:
                return "missing"
            if (
                compute_symbol_context_hash(current_symbol_context)
                != fingerprints["symbol_context_hash"]
            ):
                return "llm_refresh_required"
            if (
                compute_type_context_hash(current_symbol_context)
                != fingerprints["type_context_hash"]
            ):
                return "llm_refresh_required"

            desired = _clone_json_value(project_callees)
            desired_hash = compute_callee_summary_hash(
                {"project_callees": desired}
            )
            if snapshot.get("project_callees") == desired:
                if desired_hash != fingerprints["callee_summary_hash"]:
                    conn = self._connect()
                    try:
                        conn.execute(
                            "UPDATE snapshots SET callee_summary_hash = ?, "
                            "timestamp = CURRENT_TIMESTAMP WHERE index_name = ?",
                            (desired_hash, index_name),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                success = True
                return "unchanged"

            refreshed = _clone_snapshot(snapshot)
            refreshed["project_callees"] = desired
            snapshot_file = self._snapshot_filename(index_name)
            self._write_json_atomic(self.snapshot_dir / snapshot_file, refreshed)
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE snapshots SET callee_summary_hash = ?, "
                    "timestamp = CURRENT_TIMESTAMP, snapshot_file = ? "
                    "WHERE index_name = ?",
                    (desired_hash, snapshot_file, index_name),
                )
                conn.commit()
            finally:
                conn.close()
            self._invalidate_snapshot_cache(index_name)
            self._cache_snapshot(index_name, refreshed)
            logger.info(
                "[snapshot-reconcile] refreshed index_name=%s project_callees=%d",
                index_name,
                len(desired),
            )
            success = True
            return "refreshed"
        except Exception as exc:
            logger.exception(
                "[snapshot-reconcile] failed index_name=%s "
                "reason=callee_summary_reconcile_failed error=%s",
                index_name,
                exc,
            )
            return "failed"
        finally:
            self.lock_manager.release(index_name, success=success)

    def needs_refresh(
        self,
        index_name: str,
        current_code: str,
        current_symbol_context: Dict[str, Any],
    ) -> tuple[bool, Optional[str]]:
        snapshot = self.load_snapshot(index_name)
        if snapshot is None:
            return True, "no_snapshot"
        if snapshot is not None and (
            "callees" in snapshot
            or "callees_truncation" in snapshot
            or not isinstance(snapshot.get("referenced_macros"), list)
            or any(
                isinstance(item, dict)
                and (
                    "callee_behavior" in item
                    or "callee_summary" not in item
                    or "is_macro" in item
                )
                for item in snapshot.get("project_callees", [])
            )
            or any(
                not isinstance(item, dict)
                or set(item)
                != {
                    "macro_index_name",
                    "definition",
                    "is_function_like",
                    "reference_lines",
                }
                for item in snapshot.get("referenced_macros", [])
            )
        ):
            return True, "snapshot_shape_changed"
        if snapshot is not None and (
            not isinstance(snapshot.get("referenced_types"), list)
            or (
                "unresolved_referenced_types" in snapshot
                and (
                    not isinstance(snapshot.get("unresolved_referenced_types"), list)
                    or not snapshot.get("unresolved_referenced_types")
                )
            )
            or (
                "referenced_types_truncation" in snapshot
                and not isinstance(snapshot.get("referenced_types_truncation"), dict)
            )
        ):
            return True, "snapshot_shape_changed"
        if (
            snapshot is not None
            and str(snapshot.get("snapshot_kind") or "")
            in DETERMINISTIC_SNAPSHOT_KINDS
            and not is_current_deterministic_snapshot_shape(snapshot)
        ):
            return True, "snapshot_shape_changed"
        fingerprints = self.get_fingerprints(index_name)
        if not fingerprints:
            return True, "no_snapshot"
        if (
            compute_symbol_context_hash(current_symbol_context)
            != fingerprints["symbol_context_hash"]
        ):
            return True, "symbol_context_changed"
        current_type_hash = compute_type_context_hash(current_symbol_context)
        if current_type_hash != fingerprints["type_context_hash"]:
            logger.info(
                "[type-context] refresh index_name=%s old_hash=%s new_hash=%s "
                "reason=type_context_changed",
                index_name,
                fingerprints["type_context_hash"][:12],
                current_type_hash[:12],
            )
            return True, "type_context_changed"
        code_unchanged = compute_code_hash(current_code) == fingerprints["code_hash"]
        semantic_unchanged = (
            code_unchanged
            or compute_semantic_fingerprint(current_code) == fingerprints["semantic_hash"]
        )
        if not semantic_unchanged:
            return True, "code_changed"
        if (
            compute_callee_summary_hash(current_symbol_context)
            != fingerprints["callee_summary_hash"]
        ):
            return False, "callee_summary_changed"
        if code_unchanged:
            return False, None
        return False, "cosmetic_change_only"

    def list_snapshots(self) -> list[str]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT index_name FROM snapshots ORDER BY index_name"
            ).fetchall()
        finally:
            conn.close()
        return [str(row[0]) for row in rows]

    def delete_snapshot(self, index_name: str) -> None:
        files_to_delete: list[str] = []
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT snapshot_file, final_report_file FROM snapshots WHERE index_name = ?",
                (index_name,),
            ).fetchone()
            if row:
                for column, raw_file in (
                    ("snapshot_file", row[0]),
                    ("final_report_file", row[1]),
                ):
                    filename = str(raw_file or "")
                    if not filename:
                        continue
                    references = int(
                        conn.execute(
                            f"SELECT COUNT(*) FROM snapshots "
                            f"WHERE {column} = ? AND index_name <> ?",
                            (filename, index_name),
                        ).fetchone()[0]
                    )
                    if references == 0:
                        files_to_delete.append(filename)
                    else:
                        logger.warning(
                            "[snapshot-store] preserving shared legacy file "
                            "index_name=%s file=%s references=%d "
                            "reason=shared_storage_file",
                            index_name,
                            filename,
                            references,
                        )
            conn.execute("DELETE FROM snapshots WHERE index_name = ?", (index_name,))
            conn.commit()
        finally:
            conn.close()
        snapshot_root = self.snapshot_dir.resolve()
        for filename in dict.fromkeys(files_to_delete):
            candidate = (self.snapshot_dir / filename).resolve()
            try:
                candidate.relative_to(snapshot_root)
            except ValueError:
                logger.error(
                    "[snapshot-store] refusing to delete file outside snapshot directory "
                    "index_name=%s file=%s reason=unsafe_storage_path",
                    index_name,
                    filename,
                )
                continue
            candidate.unlink(missing_ok=True)
        self._invalidate_snapshot_cache(index_name)
        self._invalidate_final_report_cache(index_name)
        self.lock_manager.invalidate(index_name)
        logger.info("[snapshot-store] deleted index_name=%s", index_name)
