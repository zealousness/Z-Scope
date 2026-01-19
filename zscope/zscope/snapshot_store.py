"""
Snapshot storage and cache management for function semantic snapshots.
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any

from .utils import compute_code_hash, compute_semantic_fingerprint

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

    def _init_db(self) -> None:
        """Initialize SQLite database for snapshot metadata."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    func_name TEXT PRIMARY KEY,
                    code_hash TEXT NOT NULL,
                    semantic_hash TEXT NOT NULL,
                    location TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    snapshot_file TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

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
        snapshot_file = f"{func_name}.json"
        snapshot_path = self.snapshot_dir / snapshot_file

        # Save snapshot JSON
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)

        # Update metadata
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots 
                (func_name, code_hash, semantic_hash, location, snapshot_file)
                VALUES (?, ?, ?, ?, ?)
                """,
                (func_name, code_hash, semantic_hash, location, snapshot_file),
            )
            conn.commit()
            logger.info(f"Saved snapshot for function '{func_name}'")
        finally:
            conn.close()

    def load_snapshot(self, func_name: str) -> Optional[Dict[str, Any]]:
        """
        Load a function snapshot if it exists.

        Args:
            func_name: Function name

        Returns:
            Snapshot data or None if not found
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.execute(
                "SELECT snapshot_file FROM snapshots WHERE func_name = ?", (func_name,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            snapshot_path = self.snapshot_dir / row[0]
            if not snapshot_path.exists():
                logger.warning(f"Snapshot file missing for '{func_name}'")
                return None

            with open(snapshot_path, "r", encoding="utf-8") as f:
                return json.load(f)
        finally:
            conn.close()

    def get_fingerprints(self, func_name: str) -> Optional[Dict[str, str]]:
        """
        Get code fingerprints for a function.

        Args:
            func_name: Function name

        Returns:
            Dict with 'code_hash' and 'semantic_hash', or None if not found
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
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

    def needs_refresh(self, func_name: str, current_code: str) -> tuple[bool, Optional[str]]:
        """
        Check if a snapshot needs refresh based on code changes.

        Args:
            func_name: Function name
            current_code: Current function source code

        Returns:
            (needs_refresh, reason) tuple
            - If no snapshot exists: (True, "no_snapshot")
            - If code identical: (False, None)
            - If semantic change detected: (True, "code_changed")
            - If only cosmetic change: (False, None) but reason explains what changed
        """
        fingerprints = self.get_fingerprints(func_name)
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
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.execute("SELECT func_name FROM snapshots ORDER BY func_name")
            return [row[0] for row in cursor.fetchall()]
        finally:
            conn.close()

    def delete_snapshot(self, func_name: str) -> None:
        """Delete a snapshot."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.execute(
                "SELECT snapshot_file FROM snapshots WHERE func_name = ?", (func_name,)
            )
            row = cursor.fetchone()
            if row:
                snapshot_path = self.snapshot_dir / row[0]
                if snapshot_path.exists():
                    snapshot_path.unlink()
                conn.execute("DELETE FROM snapshots WHERE func_name = ?", (func_name,))
                conn.commit()
                logger.info(f"Deleted snapshot for '{func_name}'")
        finally:
            conn.close()
