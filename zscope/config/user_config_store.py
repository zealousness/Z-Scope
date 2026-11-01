"""
User configuration store for Z-SCOPE.
Manages external function descriptions, paired functions, function pointer targets,
function design intent, false positives, and config warnings.
"""

import json
import logging
import sqlite3
import threading
from types import SimpleNamespace
from pathlib import Path
from typing import Optional, Dict, Any, List, cast

from ..common.issue_identity import (
    ensure_source_context_fingerprint,
    source_context_fingerprints_compatible,
    stable_issue_fingerprint,
)
from .user_config_workbook import UserConfigWorkbook
from .project_semantics import ProjectSemanticsStore

logger = logging.getLogger(__name__)
_SQLITE_PRAGMA_LOCK = threading.Lock()


class UserConfigStore:
    """Project-semantics facade with SQLite state for scan metadata.

    XLSX is retained only as a legacy/migration backend.  Public v3 execution
    passes ``zscope.semantics.yaml`` and all interface reads then come from the
    reviewed YAML authority.
    """

    def __init__(self, user_config_path: Path):
        raw_path = Path(user_config_path)
        self.project_semantics: ProjectSemanticsStore | None = None
        self.workbook: Any
        if raw_path.suffix.lower() in {".yaml", ".yml"}:
            if raw_path.exists() and not raw_path.is_file():
                raise ValueError("project semantics path must be a YAML file")
            self.project_semantics = ProjectSemanticsStore(raw_path)
            self.db_dir = raw_path.parent / ".zscope_snapshots"
            self.workbook = SimpleNamespace(path=raw_path)
            self.db_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = self.db_dir / "user_config.state.db"
            self._init_db()
            return
        if raw_path.suffix.lower() == ".xlsx":
            if raw_path.exists() and raw_path.is_dir():
                raise ValueError("user_config path must be an .xlsx workbook or a directory.")
            self.db_dir = raw_path.parent
            workbook_path = raw_path
        else:
            if raw_path.suffix and not raw_path.exists():
                raise ValueError("user_config path must be an .xlsx workbook or a directory.")
            if raw_path.exists() and raw_path.is_file():
                raise ValueError("user_config path must be an .xlsx workbook or a directory.")
            self.db_dir = raw_path
            workbook_path = self.db_dir / "user_config.xlsx"
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.workbook = UserConfigWorkbook(workbook_path)
        self.db_path = workbook_path.with_suffix(".state.db")
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            with _SQLITE_PRAGMA_LOCK:
                conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError as exc:
            logger.debug("Unable to enable WAL for user config state DB %s: %s", self.db_path, exc)
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
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
                    stable_fingerprint TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'accepted',
                    issue_json TEXT NOT NULL DEFAULT '{}',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """
            )
            self._ensure_column(
                conn, "finding_baselines", "stable_fingerprint", "TEXT NOT NULL DEFAULT ''"
            )
            from .protocol_feedback import initialize

            initialize(conn)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_baselines_stable_fingerprint "
                "ON finding_baselines(stable_fingerprint)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_baselines_stable_updated "
                "ON finding_baselines(stable_fingerprint, updated_at DESC, id DESC)"
            )
            conn.commit()
        finally:
            conn.close()

    # ── Business Premise Feedback ──

    def get_protocol_answers(self, keys: List[str]) -> Dict[str, Dict[str, Any]]:
        from .protocol_feedback import latest

        conn = self._connect()
        try:
            return cast(Dict[str, Dict[str, Any]], latest(conn, keys))
        finally:
            conn.close()

    def protocol_answer_revisions(self, keys: List[str]) -> Dict[str, int]:
        rows = self.get_protocol_answers(keys)
        return {key: int(rows.get(key, {}).get("revision", 0)) for key in keys}

    def save_protocol_answers(self, updates: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        from .protocol_feedback import save

        conn = self._connect()
        try:
            return cast(Dict[str, Dict[str, Any]], save(conn, updates))
        finally:
            conn.close()

    # ── External Functions ──

    def upsert_external_function(
        self,
        func_name: str,
        description: str,
        library: str = "",
        memory_behavior: Optional[Dict] = None,
        concurrency_behavior: Optional[Dict] = None,
        return_semantics: str = "",
    ) -> None:
        if self.project_semantics is not None:
            raise ValueError("edit zscope.semantics.yaml or use primitive discovery")
        self.workbook.upsert_external_function(
            func_name,
            description,
            library=library,
            memory_behavior=memory_behavior,
            concurrency_behavior=concurrency_behavior,
            return_semantics=return_semantics,
        )

    def get_external_function(self, func_name: str) -> Optional[Dict[str, Any]]:
        for item in self.list_external_functions():
            if item.get("func_name") == func_name:
                return item
        return None

    def list_external_functions(self) -> List[Dict[str, Any]]:
        if self.project_semantics is not None:
            return self.project_semantics.list_external_functions()
        return cast(List[Dict[str, Any]], self.workbook.list_external_functions())

    def delete_external_function(self, func_name: str) -> None:
        if self.project_semantics is not None:
            raise ValueError("edit zscope.semantics.yaml directly")
        self.workbook.delete_external_function(func_name)

    # ── Paired Functions ──

    def upsert_paired_function(
        self, category: str, acquire_func: str, release_func: str, description: str = ""
    ) -> None:
        if self.project_semantics is not None:
            raise ValueError("edit interface pairs in zscope.semantics.yaml directly")
        self.workbook.upsert_paired_function(category, acquire_func, release_func, description)

    def list_paired_functions(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.project_semantics is not None:
            return self.project_semantics.list_paired_functions(category)
        return cast(List[Dict[str, Any]], self.workbook.list_paired_functions(category))

    def delete_paired_function(self, id: int) -> None:
        if self.project_semantics is not None:
            raise ValueError("edit interface pairs in zscope.semantics.yaml directly")
        self.workbook.delete_paired_function(id)

    # ── Function Pointer Targets ──

    def upsert_pointer_target(
        self, pointer_location: str, scope: str, target_functions: List[str], context: str = ""
    ) -> None:
        if self.project_semantics is not None:
            raise ValueError("edit function_pointer_bindings in zscope.semantics.yaml directly")
        self.workbook.upsert_pointer_target(pointer_location, scope, target_functions, context)

    def get_pointer_targets(
        self, pointer_location: Optional[str] = None, context: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if self.project_semantics is not None:
            return self.project_semantics.get_pointer_targets(pointer_location, context)
        rows = self.workbook.list_pointer_targets()
        if pointer_location:
            rows = [row for row in rows if row.get("pointer_location") == pointer_location]
        if context:
            rows = [row for row in rows if row.get("context") == context]
        return cast(List[Dict[str, Any]], rows)

    def delete_pointer_target(self, id: int) -> None:
        if self.project_semantics is not None:
            raise ValueError("edit function_pointer_bindings in zscope.semantics.yaml directly")
        self.workbook.delete_pointer_target(id)

    # ── Function Intent ──

    def list_dispatchers(self) -> List[Dict[str, Any]]:
        if self.project_semantics is not None:
            return self.project_semantics.list_dispatchers()
        return cast(List[Dict[str, Any]], self.workbook.list_dispatchers())

    def list_module_lifecycle(self) -> List[Dict[str, Any]]:
        if self.project_semantics is not None:
            return []
        return cast(List[Dict[str, Any]], self.workbook.list_module_lifecycle())

    def upsert_function_intent(
        self,
        func_name: str,
        file_path: str = "",
        caller_constraints: Optional[Dict] = None,
        concurrency_group: str = "",
        concurrent_with: Optional[List[str]] = None,
        notes: str = "",
    ) -> None:
        if self.project_semantics is not None:
            raise ValueError("function intents belong to LLM Wiki, not project semantics")
        self.workbook.upsert_function_intent(
            func_name,
            file_path=file_path,
            caller_constraints=caller_constraints,
            concurrency_group=concurrency_group,
            concurrent_with=concurrent_with,
            notes=notes,
        )

    def get_function_intent(
        self, func_name: str, file_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        if self.project_semantics is not None:
            return None
        return cast(
            Optional[Dict[str, Any]],
            self.workbook.get_function_intent(func_name, file_path),
        )

    def list_function_intents(self) -> List[Dict[str, Any]]:
        if self.project_semantics is not None:
            return []
        return cast(List[Dict[str, Any]], self.workbook.list_function_intents())

    def delete_function_intent(self, func_name: str, file_path: str = "") -> None:
        if self.project_semantics is not None:
            raise ValueError("function intents belong to LLM Wiki, not project semantics")
        self.workbook.delete_function_intent(func_name, file_path)

    # ── Config Warnings ──

    def add_config_warning(self, warning_type: str, context: str, message: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO config_warnings (warning_type, context, message)
                   VALUES (?, ?, ?)""",
                (warning_type, context, message),
            )
            conn.commit()
        finally:
            conn.close()

    def list_config_warnings(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM config_warnings ORDER BY created_at DESC").fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def clear_config_warnings(self) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM config_warnings")
            conn.commit()
        finally:
            conn.close()

    # False-positive suppressions and baselines

    def add_false_positive_suppression(
        self,
        func_name: str = "",
        location: str = "",
        category: str = "",
        reason: str = "",
        scope: str = "",
        rule: str = "",
        note: str = "",
        expires_at: str = "",
    ) -> None:
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

    def upsert_finding_baseline(
        self, dedup_key: str, status: str, issue: Optional[Dict[str, Any]] = None
    ) -> None:
        issue_payload = dict(issue or {})
        fingerprint = stable_issue_fingerprint(issue_payload)
        if fingerprint:
            issue_payload.setdefault("stable_fingerprint", fingerprint)
        ensure_source_context_fingerprint(issue_payload)
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO finding_baselines
                   (dedup_key, stable_fingerprint, status, issue_json, updated_at)
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (
                    self._normalize_key(dedup_key),
                    fingerprint,
                    status,
                    json.dumps(issue_payload, ensure_ascii=False),
                ),
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

    def get_finding_baseline_for_issue(
        self,
        issue: Dict[str, Any],
        dedup_key: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Find a baseline by exact key first, then by line-insensitive fingerprint."""
        exact_key = dedup_key or str((issue or {}).get("dedup_key") or "")
        if exact_key:
            exact = self.get_finding_baseline(exact_key)
            if exact:
                baseline_issue = self._parse_json_value(str(exact.get("issue_json") or ""), {})
                if source_context_fingerprints_compatible(issue or {}, baseline_issue):
                    exact["match_strategy"] = "dedup_key"
                    return exact

        fingerprint = stable_issue_fingerprint(issue or {})
        if not fingerprint:
            return None

        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT * FROM finding_baselines
                   WHERE stable_fingerprint = ?
                   ORDER BY updated_at DESC, id DESC
                   """,
                (fingerprint,),
            ).fetchall()
            for row in rows:
                result = self._row_to_dict(row)
                baseline_issue = self._parse_json_value(str(result.get("issue_json") or ""), {})
                if source_context_fingerprints_compatible(issue or {}, baseline_issue):
                    result["match_strategy"] = "stable_fingerprint"
                    return result

            rows = conn.execute(
                """SELECT * FROM finding_baselines
                   WHERE stable_fingerprint = ''
                   ORDER BY updated_at DESC, id DESC"""
            ).fetchall()
            for old_row in rows:
                old_issue = self._parse_json_value(old_row["issue_json"], {})
                old_fingerprint = stable_issue_fingerprint(old_issue)
                if (
                    old_fingerprint
                    and old_fingerprint == fingerprint
                    and source_context_fingerprints_compatible(issue or {}, old_issue)
                ):
                    conn.execute(
                        "UPDATE finding_baselines SET stable_fingerprint = ? WHERE id = ?",
                        (fingerprint, old_row["id"]),
                    )
                    conn.commit()
                    result = self._row_to_dict(old_row)
                    result["stable_fingerprint"] = fingerprint
                    result["match_strategy"] = "backfilled_stable_fingerprint"
                    return result
            return None
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
                lines.append(
                    f"    {it['acquire_func']} <-> {it['release_func']}"
                    + (f"  ({it['description']})" if it.get("description") else "")
                )
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

    def get_function_intent_context(self, func_name: str, file_path: Optional[str] = None) -> str:
        """Format function intent as context string for agent prompts."""
        intent = self.get_function_intent(func_name, file_path)
        if not intent:
            return ""
        lines = [f"[函数设计意图: {func_name}]"]
        if intent.get("intents"):
            lines.append(f"  用户补充: {intent['intents']}")
            return "\n".join(lines)
        constraints = intent.get("caller_constraints", "{}")
        if isinstance(constraints, str):
            constraints = self._parse_json_value(constraints, {})
        if constraints:
            lines.append(f"  调用者约束: {json.dumps(constraints, ensure_ascii=False)}")
        if intent.get("concurrency_group"):
            lines.append(f"  并发组: {intent['concurrency_group']}")
        concurrent = intent.get("concurrent_with", "[]")
        if isinstance(concurrent, str):
            concurrent = self._parse_json_value(concurrent, [])
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
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _normalize_key(value: str) -> str:
        return str(value or "").replace("\\", "/").strip().lower()

    @staticmethod
    def _parse_json_value(value: str, default: Any) -> Any:
        if not value:
            return default
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
