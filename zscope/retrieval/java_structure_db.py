"""SQLite store for Java structure frontend facts."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .java_models import JavaClassRecord


class JavaStructureDB:
    """Persist Java classes, methods, annotations, call edges, and framework IR."""

    SCHEMA_VERSION = "1"

    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS java_classes (
                    full_name TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    package TEXT DEFAULT '',
                    file_path TEXT NOT NULL,
                    start_line INTEGER DEFAULT 0,
                    end_line INTEGER DEFAULT 0,
                    kind TEXT DEFAULT 'class',
                    annotations_json TEXT DEFAULT '[]',
                    fields_json TEXT DEFAULT '{}',
                    frontend TEXT DEFAULT '',
                    precision TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS java_methods (
                    qualified_name TEXT PRIMARY KEY,
                    class_full_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    start_line INTEGER DEFAULT 0,
                    end_line INTEGER DEFAULT 0,
                    signature TEXT DEFAULT '',
                    declaration_code TEXT DEFAULT '',
                    return_type TEXT DEFAULT '',
                    parameters_json TEXT DEFAULT '[]',
                    annotations_json TEXT DEFAULT '[]',
                    class_annotations_json TEXT DEFAULT '[]',
                    calls_json TEXT DEFAULT '[]',
                    framework_semantics_json TEXT DEFAULT '{}',
                    is_declaration INTEGER DEFAULT 0,
                    is_public INTEGER DEFAULT 0,
                    is_static INTEGER DEFAULT 0,
                    frontend TEXT DEFAULT '',
                    precision TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_java_methods_class ON java_methods(class_full_name);
                CREATE INDEX IF NOT EXISTS idx_java_methods_file ON java_methods(file_path);

                CREATE TABLE IF NOT EXISTS java_call_edges (
                    id INTEGER PRIMARY KEY,
                    caller TEXT NOT NULL,
                    callee TEXT NOT NULL,
                    call_name TEXT DEFAULT '',
                    file_path TEXT DEFAULT '',
                    line INTEGER DEFAULT 0,
                    call_type TEXT DEFAULT '',
                    confidence REAL DEFAULT 0.0,
                    precision TEXT DEFAULT '',
                    UNIQUE(caller, callee, file_path, line, call_name)
                );
                CREATE INDEX IF NOT EXISTS idx_java_call_caller ON java_call_edges(caller);
                CREATE INDEX IF NOT EXISTS idx_java_call_callee ON java_call_edges(callee);
                """)
            self._conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
                (self.SCHEMA_VERSION,),
            )
            self._conn.commit()

    def replace_project(
        self, classes: Iterable[JavaClassRecord], method_metadata: Dict[str, Dict[str, Any]]
    ) -> None:
        """Replace stored Java facts for one extraction run."""
        now = str(time.time())
        with self._lock:
            self._conn.execute("DELETE FROM java_call_edges")
            self._conn.execute("DELETE FROM java_methods")
            self._conn.execute("DELETE FROM java_classes")
            for class_record in classes:
                class_precision = self._class_precision(class_record)
                class_frontend = self._class_frontend(class_record)
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO java_classes(
                        full_name, name, package, file_path, start_line, end_line, kind,
                        annotations_json, fields_json, frontend, precision
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        class_record.full_name,
                        class_record.name,
                        class_record.package,
                        class_record.file,
                        class_record.start_line,
                        class_record.end_line,
                        class_record.kind,
                        self._json([a.to_backend_dict() for a in class_record.annotations]),
                        self._json(class_record.fields),
                        class_frontend,
                        class_precision,
                    ),
                )
                for method in class_record.methods:
                    metadata = method_metadata.get(
                        method.qualified_name, method.to_method_metadata()
                    )
                    self._conn.execute(
                        """
                        INSERT OR REPLACE INTO java_methods(
                            qualified_name, class_full_name, name, file_path, start_line, end_line,
                            signature, declaration_code, return_type, parameters_json,
                            annotations_json, class_annotations_json, calls_json,
                            framework_semantics_json, is_declaration, is_public, is_static,
                            frontend, precision
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            method.qualified_name,
                            method.class_full_name,
                            method.name,
                            method.file,
                            method.start_line,
                            method.end_line,
                            method.signature,
                            method.declaration_code,
                            method.return_type,
                            self._json([p.to_backend_dict() for p in method.parameters]),
                            self._json([a.to_backend_dict() for a in method.annotations]),
                            self._json([a.to_backend_dict() for a in method.class_annotations]),
                            self._json(method.calls),
                            self._json(metadata.get("framework_semantics") or {}),
                            int(method.is_declaration),
                            int(method.is_public),
                            int(method.is_static),
                            method.frontend,
                            str(metadata.get("structure_precision") or method.precision),
                        ),
                    )
                    for call in method.calls:
                        if not isinstance(call, dict):
                            continue
                        call_name = str(call.get("name") or call.get("method") or "")
                        self._conn.execute(
                            """
                            INSERT OR IGNORE INTO java_call_edges(
                                caller, callee, call_name, file_path, line,
                                call_type, confidence, precision
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                method.qualified_name,
                                str(call.get("fullName") or call_name),
                                call_name,
                                method.file,
                                int(call.get("line") or 0),
                                str(call.get("call_type") or "source_structure"),
                                float(call.get("confidence") or 0.55),
                                str(metadata.get("structure_precision") or method.precision),
                            ),
                        )
            self._conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('last_index_time', ?)",
                (now,),
            )
            self._conn.commit()

    def method_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM java_methods").fetchone()
            return int(row["n"] if row else 0)

    def class_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM java_classes").fetchone()
            return int(row["n"] if row else 0)

    def get_method(self, qualified_name: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM java_methods WHERE qualified_name = ?",
                (qualified_name,),
            ).fetchone()
        return self._method_row(row) if row else None

    def list_call_edges(self, caller: str = "") -> List[Dict[str, Any]]:
        query = "SELECT * FROM java_call_edges"
        args: tuple[Any, ...] = ()
        if caller:
            query += " WHERE caller = ?"
            args = (caller,)
        query += " ORDER BY caller, line, callee"
        with self._lock:
            rows = self._conn.execute(query, args).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)

    @staticmethod
    def _loads(value: str, default: Any) -> Any:
        try:
            return json.loads(value or "")
        except Exception:
            return default

    @classmethod
    def _method_row(cls, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        for key, default in (
            ("parameters_json", []),
            ("annotations_json", []),
            ("class_annotations_json", []),
            ("calls_json", []),
            ("framework_semantics_json", {}),
        ):
            data[key[:-5] if key.endswith("_json") else key] = cls._loads(
                str(data.get(key) or ""), default
            )
        return data

    @staticmethod
    def _class_frontend(class_record: JavaClassRecord) -> str:
        for method in class_record.methods:
            if method.frontend:
                return method.frontend
        return "builtin"

    @staticmethod
    def _class_precision(class_record: JavaClassRecord) -> str:
        for method in class_record.methods:
            if method.precision:
                return method.precision
        return "regex_or_builtin_fallback"
