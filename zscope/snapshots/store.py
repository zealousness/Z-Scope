"""
Snapshot storage and cache management for function semantic snapshots.
"""

import json
import logging
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, Iterable, List, cast

from ..common.utils import compute_code_hash, compute_semantic_fingerprint

logger = logging.getLogger(__name__)

_SQLITE_PRAGMA_LOCK = threading.Lock()
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".ph", ".inc", ".inl"}


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


class SnapshotLockManager:
    """
    管理函数实现级别的建模互斥锁。
    确保并行扫描时，同一个函数实现同时只有一个 Worker 在建模。
    """

    def __init__(self):
        self._global_lock = threading.Lock()
        self._func_locks: Dict[str, threading.Lock] = {}
        self._modeling_status: Dict[str, str] = {}  # "idle" | "modeling" | "done" | "failed"

    @staticmethod
    def _lock_key(func_name: str, file_path: Optional[str] = None) -> str:
        normalized_path = SnapshotStore._normalize_path_hint(str(file_path or ""))
        if not normalized_path:
            return str(func_name)
        return f"{func_name}@@{normalized_path}"

    def acquire(
        self,
        func_name: str,
        timeout: float = 120.0,
        file_path: Optional[str] = None,
    ) -> str:
        """
        尝试获取某个函数实现的建模权。

        Returns:
            "acquired"  — 你拿到了锁，你负责建模
            "done"      — 其他 Worker 已经建模完毕，直接用快照
            "timeout"   — 等待超时，放弃
        """
        lock_key = self._lock_key(func_name, file_path)
        with self._global_lock:
            if lock_key not in self._func_locks:
                self._func_locks[lock_key] = threading.Lock()
                self._modeling_status[lock_key] = "idle"

            # Fast path: 已经建模完成
            if self._modeling_status[lock_key] == "done":
                return "done"

        lock = self._func_locks[lock_key]
        acquired = lock.acquire(timeout=timeout)

        if not acquired:
            return "timeout"

        # Double-check：拿到锁后再看一次状态
        with self._global_lock:
            if self._modeling_status[lock_key] == "done":
                lock.release()
                return "done"
            self._modeling_status[lock_key] = "modeling"

        return "acquired"

    def release(
        self,
        func_name: str,
        success: bool = True,
        file_path: Optional[str] = None,
    ):
        """释放建模权并标记状态。"""
        lock_key = self._lock_key(func_name, file_path)
        with self._global_lock:
            self._modeling_status[lock_key] = "done" if success else "failed"

        lock = self._func_locks.get(lock_key)
        if lock:
            try:
                lock.release()
            except RuntimeError:
                pass  # already released

    def invalidate(self, func_name: str, file_path: Optional[str] = None) -> None:
        """Allow a stale snapshot to be rebuilt in the current process."""
        lock_key = self._lock_key(func_name, file_path)
        with self._global_lock:
            if lock_key in self._modeling_status:
                self._modeling_status[lock_key] = "failed"


class SnapshotStore:
    """
    Manages persistent storage of function semantic snapshots.
    Uses SQLite for metadata and JSON files for snapshot content.
    """

    def __init__(self, snapshot_dir: Path):
        """Initialize snapshot store."""
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.snapshot_dir / "snapshots.db"
        self.lock_manager = SnapshotLockManager()
        self._snapshot_cache: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}
        self._snapshot_cache_lock = threading.Lock()
        self._final_report_cache: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}
        self._final_report_cache_lock = threading.Lock()
        self._init_db()

    def _cached_snapshot(self, func_name: str, file_path: Optional[str]) -> Optional[Dict[str, Any]]:
        with self._snapshot_cache_lock:
            snapshot = self._snapshot_cache.get((func_name, file_path))
            if snapshot is None:
                return None
            return _clone_snapshot(snapshot)

    def _cache_snapshot(self, func_name: str, file_path: Optional[str], snapshot: Dict[str, Any]) -> None:
        with self._snapshot_cache_lock:
            self._snapshot_cache[(func_name, file_path)] = _clone_snapshot(snapshot)

    def _invalidate_snapshot_cache(self, func_name: str, file_path: Optional[str] = None) -> None:
        with self._snapshot_cache_lock:
            self._snapshot_cache.pop((func_name, None), None)
            if file_path is None:
                for key in list(self._snapshot_cache):
                    if key[0] == func_name:
                        self._snapshot_cache.pop(key, None)
            else:
                self._snapshot_cache.pop((func_name, file_path), None)

    def _cached_final_report(self, func_name: str, file_path: Optional[str]) -> Optional[Dict[str, Any]]:
        with self._final_report_cache_lock:
            report = self._final_report_cache.get((func_name, file_path))
            if report is None:
                return None
            return _clone_snapshot(report)

    def _cache_final_report(self, func_name: str, file_path: Optional[str], report: Dict[str, Any]) -> None:
        with self._final_report_cache_lock:
            self._final_report_cache[(func_name, file_path)] = _clone_snapshot(report)

    def _invalidate_final_report_cache(self, func_name: str, file_path: Optional[str] = None) -> None:
        with self._final_report_cache_lock:
            self._final_report_cache.pop((func_name, None), None)
            if file_path is None:
                for key in list(self._final_report_cache):
                    if key[0] == func_name:
                        self._final_report_cache.pop(key, None)
            else:
                self._final_report_cache.pop((func_name, file_path), None)

    @classmethod
    def _preferred_rows_by_file_path(
        cls,
        rows: Iterable[Tuple[Any, ...]],
        *,
        file_path_index: int,
    ) -> List[Tuple[Any, ...]]:
        return sorted(
            list(rows),
            key=lambda row: cls._file_path_preference(str(row[file_path_index] or "")),
        )

    @staticmethod
    def _file_path_preference(file_path: str) -> Tuple[int, str]:
        suffix = Path(file_path).suffix.lower()
        if suffix in _SOURCE_SUFFIXES:
            category = 0
        elif suffix in _HEADER_SUFFIXES:
            category = 2
        else:
            category = 1
        normalized = file_path.replace("\\", "/").lstrip("./").lower()
        return category, normalized

    @staticmethod
    def _normalize_path_hint(file_path: str) -> str:
        normalized = str(file_path or "").replace("\\", "/").strip().lstrip("./")
        while "//" in normalized:
            normalized = normalized.replace("//", "/")
        return normalized.lower() if os.name == "nt" else normalized

    @classmethod
    def _paths_match_hint(cls, stored_path: str, hint_path: str) -> bool:
        stored = cls._normalize_path_hint(stored_path)
        hint = cls._normalize_path_hint(hint_path)
        if not stored or not hint:
            return False
        return (
            stored == hint
            or stored.endswith(f"/{hint}")
            or hint.endswith(f"/{stored}")
        )

    @classmethod
    def _rows_matching_file_path(
        cls,
        rows: Iterable[Tuple[Any, ...]],
        *,
        file_path: str,
        file_path_index: int,
    ) -> List[Tuple[Any, ...]]:
        row_list = list(rows)
        normalized_hint = cls._normalize_path_hint(file_path)
        exact_rows = [
            row
            for row in row_list
            if cls._normalize_path_hint(str(row[file_path_index] or "")) == normalized_hint
        ]
        if exact_rows:
            return cls._preferred_rows_by_file_path(
                exact_rows,
                file_path_index=file_path_index,
            )
        return cls._preferred_rows_by_file_path(
            [
                row
                for row in row_list
                if cls._paths_match_hint(str(row[file_path_index] or ""), file_path)
            ],
            file_path_index=file_path_index,
        )

    @staticmethod
    def _file_path_from_location(location: str) -> str:
        text = str(location or "").strip()
        if not text:
            return "unknown"
        line_suffix = re.match(r"^(.*):\d+(?:-\d+)?$", text)
        if line_suffix:
            return line_suffix.group(1) or "unknown"
        return text

    def _connect(self) -> sqlite3.Connection:
        """Create a configured SQLite connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        """Initialize SQLite database for snapshot metadata."""
        conn = self._connect()
        try:
            with _SQLITE_PRAGMA_LOCK:
                conn.execute("PRAGMA journal_mode=WAL")
            # Check if we need to migrate from old schema
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='snapshots'"
            )
            table_exists = cursor.fetchone() is not None
            
            if table_exists:
                # Check if old schema (func_name only primary key)
                cursor = conn.execute("PRAGMA table_info(snapshots)")
                columns = {row[1]: row for row in cursor.fetchall()}
                
                # If file_path column doesn't exist, we need to migrate
                if 'file_path' not in columns:
                    logger.info("Migrating snapshot database from v1 to v2 schema...")
                    self._migrate_v1_to_v2(conn)
                    # continue checking for next migrations
                    cursor = conn.execute("PRAGMA table_info(snapshots)")
                    columns = {row[1]: row for row in cursor.fetchall()}
                
                if 'final_report_file' not in columns:
                    logger.info("Migrating snapshot database to v3 schema (adding final_report_file)...")
                    conn.execute("ALTER TABLE snapshots ADD COLUMN final_report_file TEXT")
                    conn.commit()
                    return

            # Create v3 schema with composite primary key and final_report_file
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    func_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    semantic_hash TEXT NOT NULL,
                    location TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    snapshot_file TEXT NOT NULL,
                    final_report_file TEXT,
                    PRIMARY KEY (func_name, file_path)
                )
                """
            )
            conn.commit()
        finally:
            conn.close()
    
    def _migrate_v1_to_v2(self, conn: sqlite3.Connection) -> None:
        """
        Migrate from v1 schema (func_name-only PK) to v2 schema (composite PK).
        Extracts file_path from location field.
        """
        # Read all existing snapshots
        cursor = conn.execute("SELECT func_name, code_hash, semantic_hash, location, snapshot_file FROM snapshots")
        old_data = cursor.fetchall()
        
        # Drop old table
        conn.execute("DROP TABLE snapshots")
        
        # Create new schema
        conn.execute(
            """
            CREATE TABLE snapshots (
                func_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                semantic_hash TEXT NOT NULL,
                location TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                snapshot_file TEXT NOT NULL,
                final_report_file TEXT,
                PRIMARY KEY (func_name, file_path)
            )
            """
        )
        
        # Migrate data
        for func_name, code_hash, semantic_hash, location, snapshot_file in old_data:
            # Extract file_path from location (format: "path/to/file.c:start-end")
            file_path = self._file_path_from_location(location)
            
            conn.execute(
                """
                INSERT INTO snapshots 
                (func_name, file_path, code_hash, semantic_hash, location, snapshot_file)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (func_name, file_path, code_hash, semantic_hash, location, snapshot_file)
            )
        
        conn.commit()
        logger.info(f"Migrated {len(old_data)} snapshots to v2 schema")


    def save_snapshot(
        self, func_name: str, snapshot: Dict[str, Any], code: str, location: str
    ) -> None:
        """
        Save a function snapshot with code fingerprints.

        Args:
            func_name: Function name
            snapshot: Snapshot JSON data
            code: Function source code
            location: Function location (file:line-line)
        """
        code_hash = compute_code_hash(code)
        semantic_hash = compute_semantic_fingerprint(code)
        
        # Extract file_path from location
        file_path = self._file_path_from_location(location)
        
        # Create unique snapshot filename with sanitized path
        safe_path = file_path.replace('/', '_').replace('\\', '_').replace(':', '')
        snapshot_file = f"{func_name}_{safe_path}.json"
        snapshot_path = self.snapshot_dir / snapshot_file

        # Save snapshot JSON
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)

        # Update metadata
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots 
                (func_name, file_path, code_hash, semantic_hash, location, snapshot_file)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (func_name, file_path, code_hash, semantic_hash, location, snapshot_file),
            )
            conn.commit()
            self._invalidate_snapshot_cache(func_name, file_path)
            self._invalidate_final_report_cache(func_name, file_path)
            self._cache_snapshot(func_name, file_path, snapshot)
            logger.info(f"Saved snapshot for function '{func_name}' at '{file_path}'")
        finally:
            conn.close()

    def save_final_report(
        self, func_name: str, final_report: Dict[str, Any], location: str
    ) -> None:
        """
        Save the final vulnerability report to disk and update metadata in DB.
        """
        file_path = self._file_path_from_location(location)

        conn = self._connect()
        try:
            target_file_path = file_path
            cursor = conn.execute(
                "SELECT file_path FROM snapshots WHERE func_name = ?",
                (func_name,),
            )
            rows = self._rows_matching_file_path(
                cursor.fetchall(),
                file_path=file_path,
                file_path_index=0,
            )
            if len(rows) > 1:
                paths = [r[0] for r in rows]
                logger.warning(
                    "Not attaching final report for function '%s' with ambiguous path hint '%s'; matched %s.",
                    func_name,
                    file_path,
                    paths,
                )
                rows = []
            if rows:
                target_file_path = str(rows[0][0] or file_path)

            safe_path = target_file_path.replace('/', '_').replace('\\', '_').replace(':', '')
            final_file = f"{func_name}_{safe_path}_final.json"
            final_path = self.snapshot_dir / final_file

            with open(final_path, "w", encoding="utf-8") as f:
                json.dump(final_report, f, indent=2, ensure_ascii=False)

            cursor = conn.execute(
                """
                UPDATE snapshots 
                SET final_report_file = ?
                WHERE func_name = ? AND file_path = ?
                """,
                (final_file, func_name, target_file_path),
            )
            conn.commit()
            self._invalidate_final_report_cache(func_name, target_file_path)
            if cursor.rowcount > 0:
                self._cache_final_report(func_name, target_file_path, final_report)
            else:
                logger.warning(
                    "Saved final report file for function '%s' at '%s', but no matching snapshot row was found.",
                    func_name,
                    file_path,
                )
            logger.info(f"Saved final report for function '{func_name}' at '{target_file_path}'")
        finally:
            conn.close()

    def load_snapshot(self, func_name: str, file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Load a function snapshot if it exists.

        Args:
            func_name: Function name
            file_path: Optional file path for disambiguation. If None and multiple
                      snapshots exist, prefers source files over headers.

        Returns:
            Snapshot data or None if not found
        """
        cached = self._cached_snapshot(func_name, file_path)
        if cached is not None:
            return cached

        conn = self._connect()
        try:
            if file_path:
                cursor = conn.execute(
                    "SELECT snapshot_file, file_path FROM snapshots WHERE func_name = ?",
                    (func_name,)
                )
                rows = self._rows_matching_file_path(
                    cursor.fetchall(),
                    file_path=file_path,
                    file_path_index=1,
                )
            else:
                # Query all matches for this function name
                cursor = conn.execute(
                    "SELECT snapshot_file, file_path FROM snapshots WHERE func_name = ?",
                    (func_name,)
                )
                rows = self._preferred_rows_by_file_path(
                    cursor.fetchall(),
                    file_path_index=1,
                )
                
            if not rows:
                return None
            
            # If no file_path specified, check if there are multiple matches
            if not file_path:
                if len(rows) > 1:
                    paths = [r[1] for r in rows]
                    logger.warning(
                        f"Multiple snapshots found for '{func_name}' in {paths}. "
                        f"Using preferred match '{rows[0][1]}'. "
                        f"Specify file_path for exact match."
                    )
            elif len(rows) > 1:
                paths = [r[1] for r in rows]
                logger.warning(
                    f"Multiple snapshots matched '{func_name}' with path hint '{file_path}' in {paths}. "
                    "Skipping ambiguous match."
                )
                return None
            for row in rows:
                selected_file_path = row[1]
                snapshot_path = self.snapshot_dir / row[0]
                if not snapshot_path.exists():
                    logger.warning(f"Snapshot file missing for '{func_name}' at '{selected_file_path}'")
                    if file_path:
                        return None
                    continue

                with open(snapshot_path, "r", encoding="utf-8") as f:
                    snapshot = cast(Dict[str, Any], json.load(f))
                self._cache_snapshot(func_name, selected_file_path, snapshot)
                if not file_path:
                    self._cache_snapshot(func_name, None, snapshot)
                return _clone_snapshot(snapshot)
            return None
        finally:
            conn.close()

    def load_final_report(self, func_name: str, file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Load a final vulnerability report if it exists.
        """
        cached = self._cached_final_report(func_name, file_path)
        if cached is not None:
            return cached

        conn = self._connect()
        try:
            if file_path:
                cursor = conn.execute(
                    "SELECT final_report_file, file_path FROM snapshots WHERE func_name = ?",
                    (func_name,)
                )
                rows = self._rows_matching_file_path(
                    cursor.fetchall(),
                    file_path=file_path,
                    file_path_index=1,
                )
            else:
                cursor = conn.execute(
                    "SELECT final_report_file, file_path FROM snapshots WHERE func_name = ?",
                    (func_name,)
                )
                rows = self._preferred_rows_by_file_path(
                    cursor.fetchall(),
                    file_path_index=1,
                )
                
            rows = [row for row in rows if row[0]]
            if not rows:
                return None
            
            if not file_path:
                if len(rows) > 1:
                    paths = [r[1] for r in rows]
                    logger.warning(
                        f"Multiple final reports found for '{func_name}' in {paths}. "
                        f"Using preferred match '{rows[0][1]}'. "
                        f"Specify file_path for exact match."
                    )
            elif len(rows) > 1:
                paths = [r[1] for r in rows]
                logger.warning(
                    f"Multiple final reports matched '{func_name}' with path hint '{file_path}' in {paths}. "
                    "Skipping ambiguous match."
                )
                return None

            for row in rows:
                selected_file_path = row[1]
                final_path = self.snapshot_dir / row[0]
                if not final_path.exists():
                    logger.warning(f"Final report file missing for '{func_name}' at '{selected_file_path}'")
                    if file_path:
                        return None
                    continue

                with open(final_path, "r", encoding="utf-8") as f:
                    report = cast(Dict[str, Any], json.load(f))
                self._cache_final_report(func_name, selected_file_path, report)
                if not file_path:
                    self._cache_final_report(func_name, None, report)
                return _clone_snapshot(report)
            return None
        finally:
            conn.close()

    def get_fingerprints(self, func_name: str, file_path: Optional[str] = None) -> Optional[Dict[str, str]]:
        """
        Get code fingerprints for a function.

        Args:
            func_name: Function name
            file_path: Optional file path for disambiguation

        Returns:
            Dict with 'code_hash' and 'semantic_hash', or None if not found
        """
        conn = self._connect()
        try:
            if file_path:
                cursor = conn.execute(
                    "SELECT code_hash, semantic_hash, file_path FROM snapshots WHERE func_name = ?",
                    (func_name,),
                )
                rows = self._rows_matching_file_path(
                    cursor.fetchall(),
                    file_path=file_path,
                    file_path_index=2,
                )
                if len(rows) > 1:
                    paths = [r[2] for r in rows]
                    logger.warning(
                        "Multiple fingerprints matched '%s' with path hint '%s' in %s. Skipping ambiguous match.",
                        func_name,
                        file_path,
                        paths,
                    )
                    return None
                row = rows[0] if rows else None
            else:
                cursor = conn.execute(
                    "SELECT code_hash, semantic_hash, file_path FROM snapshots WHERE func_name = ?",
                    (func_name,),
                )
                rows = self._preferred_rows_by_file_path(
                    cursor.fetchall(),
                    file_path_index=2,
                )
                row = rows[0] if rows else None
            if not row:
                return None
            return {"code_hash": row[0], "semantic_hash": row[1]}
        finally:
            conn.close()

    def needs_refresh(self, func_name: str, current_code: str, file_path: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
        Check if a snapshot needs refresh based on code changes.

        Args:
            func_name: Function name
            current_code: Current function source code
            file_path: Optional file path for disambiguation

        Returns:
            (needs_refresh, reason) tuple
            - If no snapshot exists: (True, "no_snapshot")
            - If code identical: (False, None)
            - If semantic change detected: (True, "code_changed")
            - If only cosmetic change: (False, None) but reason explains what changed
        """
        fingerprints = self.get_fingerprints(func_name, file_path)
        if not fingerprints:
            return (True, "no_snapshot")

        current_hash = compute_code_hash(current_code)
        current_semantic = compute_semantic_fingerprint(current_code)

        # Exact match - no refresh needed
        if current_hash == fingerprints["code_hash"]:
            return (False, None)

        # Semantic match - likely just cosmetic changes
        if current_semantic == fingerprints["semantic_hash"]:
            return (False, "cosmetic_change_only")

        # Semantic change detected - needs refresh
        return (True, "code_changed")

    def list_snapshots(self) -> list[str]:
        """List all function names with snapshots."""
        conn = self._connect()
        try:
            cursor = conn.execute("SELECT func_name, file_path FROM snapshots ORDER BY func_name")
            return [f"{row[0]} ({row[1]})" for row in cursor.fetchall()]
        finally:
            conn.close()

    def delete_snapshot(self, func_name: str, file_path: Optional[str] = None) -> None:
        """Delete a snapshot."""
        conn = self._connect()
        try:
            if file_path:
                cursor = conn.execute(
                    "SELECT snapshot_file, final_report_file FROM snapshots WHERE func_name = ? AND file_path = ?",
                    (func_name, file_path)
                )
                row = cursor.fetchone()
                if row:
                    snapshot_path = self.snapshot_dir / row[0]
                    if snapshot_path.exists(): snapshot_path.unlink()
                    if row[1]:
                        final_path = self.snapshot_dir / row[1]
                        if final_path.exists(): final_path.unlink()
                conn.execute(
                        "DELETE FROM snapshots WHERE func_name = ? AND file_path = ?",
                        (func_name, file_path)
                )
                conn.commit()
                self._invalidate_snapshot_cache(func_name, file_path)
                self._invalidate_final_report_cache(func_name, file_path)
                logger.info(f"Deleted snapshot for '{func_name}' at '{file_path}'")
            else:
                # Delete all snapshots
                cursor = conn.execute(
                    "SELECT snapshot_file, final_report_file FROM snapshots WHERE func_name = ?",
                    (func_name,)
                )
                for row in cursor.fetchall():
                    snapshot_path = self.snapshot_dir / row[0]
                    if snapshot_path.exists(): snapshot_path.unlink()
                    if row[1]:
                        final_path = self.snapshot_dir / row[1]
                        if final_path.exists(): final_path.unlink()
                conn.execute("DELETE FROM snapshots WHERE func_name = ?", (func_name,))
                conn.commit()
                self._invalidate_snapshot_cache(func_name)
                self._invalidate_final_report_cache(func_name)
                logger.info(f"Deleted all snapshots for '{func_name}'")
        finally:
            conn.close()
