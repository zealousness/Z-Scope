"""
Snapshot storage and cache management for function semantic snapshots.
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any

from ..common.utils import compute_code_hash, compute_semantic_fingerprint

logger = logging.getLogger(__name__)


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
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        """Create a configured SQLite connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        """Initialize SQLite database for snapshot metadata."""
        conn = self._connect()
        try:
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
                    return
            
            # Create v2 schema with composite primary key
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
                PRIMARY KEY (func_name, file_path)
            )
            """
        )
        
        # Migrate data
        for func_name, code_hash, semantic_hash, location, snapshot_file in old_data:
            # Extract file_path from location (format: "path/to/file.c:start-end")
            file_path = location.split(':')[0] if ':' in location else 'unknown'
            
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
        file_path = location.split(':')[0] if ':' in location else 'unknown'
        
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
            logger.info(f"Saved snapshot for function '{func_name}' at '{file_path}'")
        finally:
            conn.close()

    def load_snapshot(self, func_name: str, file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Load a function snapshot if it exists.

        Args:
            func_name: Function name
            file_path: Optional file path for disambiguation. If None and multiple
                      snapshots exist, returns the first one with a warning.

        Returns:
            Snapshot data or None if not found
        """
        conn = self._connect()
        try:
            if file_path:
                # Exact match query
                cursor = conn.execute(
                    "SELECT snapshot_file FROM snapshots WHERE func_name = ? AND file_path = ?",
                    (func_name, file_path)
                )
            else:
                # Query all matches for this function name
                cursor = conn.execute(
                    "SELECT snapshot_file, file_path FROM snapshots WHERE func_name = ?",
                    (func_name,)
                )
                
            row = cursor.fetchone()
            if not row:
                return None
            
            # If no file_path specified, check if there are multiple matches
            if not file_path:
                all_rows = [row] + cursor.fetchall()
                if len(all_rows) > 1:
                    paths = [r[1] for r in all_rows]
                    logger.warning(
                        f"Multiple snapshots found for '{func_name}' in {paths}. "
                        f"Using first match. Specify file_path for exact match."
                    )

            snapshot_path = self.snapshot_dir / row[0]
            if not snapshot_path.exists():
                logger.warning(f"Snapshot file missing for '{func_name}'")
                return None

            with open(snapshot_path, "r", encoding="utf-8") as f:
                return json.load(f)
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
                    "SELECT code_hash, semantic_hash FROM snapshots WHERE func_name = ? AND file_path = ?",
                    (func_name, file_path),
                )
            else:
                cursor = conn.execute(
                    "SELECT code_hash, semantic_hash FROM snapshots WHERE func_name = ?",
                    (func_name,),
                )
            row = cursor.fetchone()
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
                    "SELECT snapshot_file FROM snapshots WHERE func_name = ? AND file_path = ?",
                    (func_name, file_path)
                )
                row = cursor.fetchone()
                if row:
                    snapshot_path = self.snapshot_dir / row[0]
                    if snapshot_path.exists():
                        snapshot_path.unlink()
                    conn.execute(
                        "DELETE FROM snapshots WHERE func_name = ? AND file_path = ?",
                        (func_name, file_path)
                    )
                    conn.commit()
                    logger.info(f"Deleted snapshot for '{func_name}' at '{file_path}'")
            else:
                # Delete all snapshots for this function
                cursor = conn.execute(
                    "SELECT snapshot_file FROM snapshots WHERE func_name = ?",
                    (func_name,)
                )
                for row in cursor.fetchall():
                    snapshot_path = self.snapshot_dir / row[0]
                    if snapshot_path.exists():
                        snapshot_path.unlink()
                conn.execute("DELETE FROM snapshots WHERE func_name = ?", (func_name,))
                conn.commit()
                logger.info(f"Deleted all snapshots for '{func_name}'")
        finally:
            conn.close()
