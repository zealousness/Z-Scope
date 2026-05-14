"""
User configuration store for Z-SCOPE.
Manages external function descriptions, paired functions, function pointer targets,
function design intent, false positives, and config warnings.
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


class UserConfigStore:
    """SQLite-backed store for user-provided analysis configuration."""

    def __init__(self, db_dir: Path):
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / "user_config.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS external_functions (
                    func_name TEXT PRIMARY KEY,
                    library TEXT DEFAULT '',
                    description TEXT NOT NULL,
                    memory_behavior TEXT DEFAULT '{}',
                    concurrency_behavior TEXT DEFAULT '{}',
                    return_semantics TEXT DEFAULT '',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS function_pointer_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pointer_location TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'local',
                    target_functions TEXT NOT NULL DEFAULT '[]',
                    context TEXT DEFAULT '',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(pointer_location, context)
                );

                CREATE TABLE IF NOT EXISTS paired_functions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    acquire_func TEXT NOT NULL,
                    release_func TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(acquire_func, release_func)
                );

                CREATE TABLE IF NOT EXISTS function_intent (
                    func_name TEXT NOT NULL,
                    file_path TEXT NOT NULL DEFAULT '',
                    caller_constraints TEXT DEFAULT '{}',
                    concurrency_group TEXT DEFAULT '',
                    concurrent_with TEXT DEFAULT '[]',
                    notes TEXT DEFAULT '',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (func_name, file_path)
                );

                CREATE TABLE IF NOT EXISTS config_warnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    warning_type TEXT NOT NULL,
                    context TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS finding_suppressions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    func_name TEXT NOT NULL DEFAULT '',
                    location TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '',
                    scope TEXT NOT NULL DEFAULT '',
                    rule TEXT NOT NULL DEFAULT '',
                    reason TEXT DEFAULT '',
                    note TEXT DEFAULT '',
                    expires_at DATETIME DEFAULT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(func_name, location, category)
                );

                CREATE TABLE IF NOT EXISTS finding_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedup_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'accepted',
                    issue_json TEXT NOT NULL DEFAULT '{}',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
        finally:
            conn.close()

    # ── External Functions ──

    def upsert_external_function(self, func_name: str, description: str,
                                 library: str = "", memory_behavior: Optional[Dict] = None,
                                 concurrency_behavior: Optional[Dict] = None,
                                 return_semantics: str = "") -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO external_functions
                   (func_name, library, description, memory_behavior,
                    concurrency_behavior, return_semantics, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (func_name, library, description,
                 json.dumps(memory_behavior or {}),
                 json.dumps(concurrency_behavior or {}),
                 return_semantics))
            conn.commit()
        finally:
            conn.close()

    def get_external_function(self, func_name: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM external_functions WHERE func_name = ?",
                (func_name,)).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_external_functions(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM external_functions ORDER BY func_name").fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def delete_external_function(self, func_name: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM external_functions WHERE func_name = ?", (func_name,))
            conn.commit()
        finally:
            conn.close()

    # ── Paired Functions ──

    def upsert_paired_function(self, category: str, acquire_func: str,
                               release_func: str, description: str = "") -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO paired_functions
                   (category, acquire_func, release_func, description, updated_at)
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (category, acquire_func, release_func, description))
            conn.commit()
        finally:
            conn.close()

    def list_paired_functions(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            if category:
                rows = conn.execute(
                    "SELECT * FROM paired_functions WHERE category = ? ORDER BY acquire_func",
                    (category,)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM paired_functions ORDER BY category, acquire_func").fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def delete_paired_function(self, id: int) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM paired_functions WHERE id = ?", (id,))
            conn.commit()
        finally:
            conn.close()

    # ── Function Pointer Targets ──

    def upsert_pointer_target(self, pointer_location: str, scope: str,
                              target_functions: List[str], context: str = "") -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO function_pointer_targets
                   (pointer_location, scope, target_functions, context, updated_at)
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (pointer_location, scope, json.dumps(target_functions), context))
            conn.commit()
        finally:
            conn.close()

    def get_pointer_targets(self, pointer_location: Optional[str] = None,
                            context: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            if pointer_location and context:
                rows = conn.execute(
                    "SELECT * FROM function_pointer_targets WHERE pointer_location = ? AND context = ?",
                    (pointer_location, context)).fetchall()
            elif pointer_location:
                rows = conn.execute(
                    "SELECT * FROM function_pointer_targets WHERE pointer_location = ?",
                    (pointer_location,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM function_pointer_targets").fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def delete_pointer_target(self, id: int) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM function_pointer_targets WHERE id = ?", (id,))
            conn.commit()
        finally:
            conn.close()

    # ── Function Intent ──

    def upsert_function_intent(self, func_name: str, file_path: str = "",
                               caller_constraints: Optional[Dict] = None,
                               concurrency_group: str = "",
                               concurrent_with: Optional[List[str]] = None,
                               notes: str = "") -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO function_intent
                   (func_name, file_path, caller_constraints, concurrency_group,
                    concurrent_with, notes, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (func_name, file_path,
                 json.dumps(caller_constraints or {}),
                 concurrency_group,
                 json.dumps(concurrent_with or []),
                 notes))
            conn.commit()
        finally:
            conn.close()

    def get_function_intent(self, func_name: str,
                            file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            if file_path:
                row = conn.execute(
                    "SELECT * FROM function_intent WHERE func_name = ? AND file_path = ?",
                    (func_name, file_path)).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM function_intent WHERE func_name = ?",
                    (func_name,)).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_function_intents(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM function_intent ORDER BY func_name").fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def delete_function_intent(self, func_name: str, file_path: str = "") -> None:
        conn = self._connect()
        try:
            conn.execute(
                "DELETE FROM function_intent WHERE func_name = ? AND file_path = ?",
                (func_name, file_path))
            conn.commit()
        finally:
            conn.close()

    # ── Config Warnings ──

    def add_config_warning(self, warning_type: str, context: str,
                           message: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO config_warnings (warning_type, context, message)
                   VALUES (?, ?, ?)""",
                (warning_type, context, message))
            conn.commit()
        finally:
            conn.close()

    def list_config_warnings(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM config_warnings ORDER BY created_at DESC").fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def clear_config_warnings(self) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM config_warnings")
            conn.commit()
            for column, decl in (
                ("scope", "TEXT NOT NULL DEFAULT ''"),
                ("rule", "TEXT NOT NULL DEFAULT ''"),
                ("note", "TEXT DEFAULT ''"),
                ("expires_at", "DATETIME DEFAULT NULL"),
            ):
                try:
                    conn.execute(f"ALTER TABLE finding_suppressions ADD COLUMN {column} {decl}")
                    conn.commit()
                except sqlite3.OperationalError:
                    pass
        finally:
            conn.close()

    # False-positive suppressions and baselines

    def add_false_positive_suppression(self, func_name: str = "",
                                       location: str = "",
                                       category: str = "",
                                       reason: str = "",
                                       scope: str = "",
                                       rule: str = "",
                                       note: str = "",
                                       expires_at: str = "") -> None:
        """Persist a false-positive suppression.

        Empty fields act as wildcards during lookup, so callers can suppress by
        exact location, whole function/category, or category-only.
        """
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO finding_suppressions
                   (func_name, location, category, scope, rule, reason, note, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), CURRENT_TIMESTAMP)""",
                (
                    self._normalize_key(func_name),
                    self._normalize_key(location),
                    self._normalize_key(category),
                    self._normalize_key(scope),
                    self._normalize_key(rule),
                    reason,
                    note,
                    expires_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def is_false_positive(self, func_name: str, location: str, category: str) -> bool:
        """Return whether a finding is marked as a false positive."""
        func = self._normalize_key(func_name)
        loc = self._normalize_key(location)
        cat = self._normalize_key(category)
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT func_name, location, category FROM finding_suppressions
                   WHERE (func_name = '' OR func_name = ?)
                     AND (location = '' OR location = ?)
                     AND (category = '' OR category = ?)
                     AND (expires_at IS NULL OR expires_at = '' OR expires_at > CURRENT_TIMESTAMP)""",
                (func, loc, cat),
            ).fetchall()
            return bool(rows)
        finally:
            conn.close()

    def upsert_finding_baseline(self, dedup_key: str, status: str,
                                issue: Optional[Dict[str, Any]] = None) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO finding_baselines
                   (dedup_key, status, issue_json, updated_at)
                   VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                (self._normalize_key(dedup_key), status, json.dumps(issue or {}, ensure_ascii=False)),
            )
            conn.commit()
        finally:
            conn.close()

    def get_finding_baseline(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM finding_baselines WHERE dedup_key = ?",
                (self._normalize_key(dedup_key),),
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    # ── Context Injection Helpers ──

    def get_paired_functions_context(self) -> str:
        """Format paired functions as context string for agent prompts."""
        pairs = self.list_paired_functions()
        if not pairs:
            return ""
        lines = ["[用户配置的配对函数]"]
        by_cat: Dict[str, list] = {}
        for p in pairs:
            by_cat.setdefault(p["category"], []).append(p)
        for cat, items in by_cat.items():
            lines.append(f"  类别: {cat}")
            for it in items:
                lines.append(f"    {it['acquire_func']} <-> {it['release_func']}"
                             + (f"  ({it['description']})" if it.get("description") else ""))
        return "\n".join(lines)

    def get_pointer_targets_context(self) -> str:
        """Format user-provided function pointer targets as context string."""
        targets = self.get_pointer_targets()
        if not targets:
            return ""
        lines = ["[用户配置的函数指针指向]"]
        for target in targets:
            funcs = target.get("target_functions", "[]")
            if isinstance(funcs, str):
                try:
                    funcs = json.loads(funcs)
                except json.JSONDecodeError:
                    funcs = [funcs]
            lines.append(
                f"  {target['pointer_location']} -> {', '.join(funcs)}"
                + (f"  (scope: {target['scope']})" if target.get("scope") else "")
                + (f"  ({target['context']})" if target.get("context") else "")
            )
        return "\n".join(lines)

    def get_function_intent_context(self, func_name: str,
                                    file_path: Optional[str] = None) -> str:
        """Format function intent as context string for agent prompts."""
        intent = self.get_function_intent(func_name, file_path)
        if not intent:
            return ""
        lines = [f"[函数设计意图: {func_name}]"]
        constraints = intent.get("caller_constraints", "{}")
        if isinstance(constraints, str):
            constraints = json.loads(constraints)
        if constraints:
            lines.append(f"  调用者约束: {json.dumps(constraints, ensure_ascii=False)}")
        if intent.get("concurrency_group"):
            lines.append(f"  并发组: {intent['concurrency_group']}")
        concurrent = intent.get("concurrent_with", "[]")
        if isinstance(concurrent, str):
            concurrent = json.loads(concurrent)
        if concurrent:
            lines.append(f"  与以下组存在并发: {', '.join(concurrent)}")
        if intent.get("notes"):
            lines.append(f"  备注: {intent['notes']}")
        return "\n".join(lines)

    # ── Helper ──

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _normalize_key(value: str) -> str:
        return str(value or "").replace("\\", "/").strip().lower()
