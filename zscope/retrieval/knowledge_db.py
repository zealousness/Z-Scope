"""
SQLite knowledge database for storing extracted code structure.
Persists function signatures, type definitions, call graph, macros, etc.
"""

import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

logger = logging.getLogger(__name__)


class KnowledgeDB:
    """SQLite-backed code knowledge store."""

    SCHEMA_VERSION = "7"

    def __init__(self, db_path: str):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connections_lock = threading.RLock()
        self._thread_local = threading.local()
        self._connections: List[sqlite3.Connection] = []
        self._closed = False
        self._create_tables()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self._db_path),
            timeout=30.0,
            check_same_thread=False,
        )
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError as exc:
            logger.debug("Unable to enable WAL for %s: %s", self._db_path, exc)
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        """Return the SQLite connection owned by the current worker thread."""
        with self._connections_lock:
            if self._closed:
                raise RuntimeError("KnowledgeDB is closed")
            conn = getattr(self._thread_local, "conn", None)
            if conn is None:
                conn = self._connect()
                self._thread_local.conn = conn
                self._connections.append(conn)
            return conn

    def _create_tables(self):
        c = self._conn
        c.executescript("""
            CREATE TABLE IF NOT EXISTS translation_units (
                id          INTEGER PRIMARY KEY,
                file_path   TEXT NOT NULL UNIQUE,
                last_modified REAL,
                index_time  REAL,
                status      TEXT DEFAULT 'pending',
                file_hash   TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS functions (
                id          INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                start_line  INTEGER NOT NULL,
                end_line    INTEGER NOT NULL,
                signature   TEXT,
                is_static   INTEGER DEFAULT 0,
                is_inline   INTEGER DEFAULT 0,
                is_declaration INTEGER DEFAULT 0,
                tu_id       INTEGER REFERENCES translation_units(id),
                UNIQUE(name, file_path, start_line)
            );
            CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);

            CREATE TABLE IF NOT EXISTS type_definitions (
                id          INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                kind        TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                start_line  INTEGER NOT NULL,
                end_line    INTEGER NOT NULL,
                full_definition TEXT,
                tu_id       INTEGER REFERENCES translation_units(id),
                UNIQUE(name, kind, file_path)
            );
            CREATE INDEX IF NOT EXISTS idx_types_name ON type_definitions(name);

            CREATE TABLE IF NOT EXISTS type_members (
                id          INTEGER PRIMARY KEY,
                type_id     INTEGER NOT NULL REFERENCES type_definitions(id),
                member_name TEXT NOT NULL,
                member_type TEXT,
                offset_idx  INTEGER,
                UNIQUE(type_id, member_name)
            );

            CREATE TABLE IF NOT EXISTS call_edges (
                id          INTEGER PRIMARY KEY,
                caller_name TEXT NOT NULL,
                caller_file TEXT NOT NULL,
                callee_name TEXT NOT NULL,
                callee_file TEXT DEFAULT '',
                call_line   INTEGER,
                call_type   TEXT DEFAULT 'direct',
                UNIQUE(caller_name, caller_file, callee_name, callee_file, call_line)
            );
            CREATE INDEX IF NOT EXISTS idx_call_caller ON call_edges(caller_name);
            CREATE INDEX IF NOT EXISTS idx_call_callee ON call_edges(callee_name);

            CREATE TABLE IF NOT EXISTS macro_definitions (
                id          INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                definition  TEXT,
                is_function_like INTEGER DEFAULT 0,
                UNIQUE(name, file_path, line)
            );
            CREATE INDEX IF NOT EXISTS idx_macros_name ON macro_definitions(name);

            CREATE TABLE IF NOT EXISTS global_variables (
                id          INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                type_str    TEXT,
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                is_extern   INTEGER DEFAULT 0,
                UNIQUE(name, file_path)
            );

            CREATE TABLE IF NOT EXISTS include_edges (
                id          INTEGER PRIMARY KEY,
                source_file TEXT NOT NULL,
                included_file TEXT NOT NULL,
                line        INTEGER,
                is_system   INTEGER DEFAULT 0,
                UNIQUE(source_file, included_file, line)
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key         TEXT PRIMARY KEY,
                value       TEXT
            );

            CREATE TABLE IF NOT EXISTS indirect_calls (
                id          INTEGER PRIMARY KEY,
                caller_name TEXT NOT NULL,
                callee_name TEXT NOT NULL,
                call_file   TEXT DEFAULT '',
                call_line   INTEGER DEFAULT 0,
                source      TEXT DEFAULT 'svf-ander',
                confidence  REAL DEFAULT 1.0,
                svf_group   TEXT DEFAULT 'default',
                UNIQUE(caller_name, callee_name, source, svf_group)
            );
            CREATE INDEX IF NOT EXISTS idx_ic_caller ON indirect_calls(caller_name);
            CREATE INDEX IF NOT EXISTS idx_ic_callee ON indirect_calls(callee_name);
            CREATE INDEX IF NOT EXISTS idx_ic_file_line ON indirect_calls(call_file, call_line);

            CREATE TABLE IF NOT EXISTS taint_signatures (
                id          INTEGER PRIMARY KEY,
                source_func TEXT,
                sink_func   TEXT,
                bug_type    TEXT NOT NULL,
                file_path   TEXT,
                line        INTEGER DEFAULT 0,
                tool        TEXT DEFAULT 'saber',
                svf_group   TEXT DEFAULT 'default',
                UNIQUE(bug_type, file_path, line, svf_group)
            );
            CREATE INDEX IF NOT EXISTS idx_taint_type ON taint_signatures(bug_type);

            CREATE TABLE IF NOT EXISTS ir_statements (
                id          INTEGER PRIMARY KEY,
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                function    TEXT NOT NULL,
                kind        TEXT DEFAULT '',
                normalized_code TEXT DEFAULT '',
                ast_kind    TEXT DEFAULT '',
                defs        TEXT DEFAULT '[]',
                uses        TEXT DEFAULT '[]',
                UNIQUE(file_path, line, function, normalized_code)
            );
            CREATE INDEX IF NOT EXISTS idx_ir_stmt_func ON ir_statements(function);
            CREATE INDEX IF NOT EXISTS idx_ir_stmt_file_line ON ir_statements(file_path, line);

            CREATE TABLE IF NOT EXISTS ir_cfg_edges (
                id          INTEGER PRIMARY KEY,
                function    TEXT NOT NULL,
                from_stmt   INTEGER,
                to_stmt     INTEGER,
                edge_kind   TEXT DEFAULT '',
                condition   TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_ir_cfg_func ON ir_cfg_edges(function);

            CREATE TABLE IF NOT EXISTS ir_def_use_edges (
                id          INTEGER PRIMARY KEY,
                variable    TEXT NOT NULL,
                object_id   TEXT DEFAULT '',
                def_stmt    INTEGER,
                use_stmt    INTEGER,
                may_alias   INTEGER DEFAULT 0,
                confidence  REAL DEFAULT 0.5
            );
            CREATE INDEX IF NOT EXISTS idx_ir_du_var ON ir_def_use_edges(variable);

            CREATE TABLE IF NOT EXISTS ir_resource_events (
                id          INTEGER PRIMARY KEY,
                candidate_id TEXT DEFAULT '',
                object_id   TEXT DEFAULT '',
                event_kind  TEXT NOT NULL,
                api         TEXT DEFAULT '',
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                function    TEXT NOT NULL,
                owner_before TEXT DEFAULT '',
                owner_after TEXT DEFAULT '',
                condition   TEXT DEFAULT '',
                confidence  REAL DEFAULT 0.5
            );
            CREATE INDEX IF NOT EXISTS idx_ir_resource_candidate ON ir_resource_events(candidate_id);
            CREATE INDEX IF NOT EXISTS idx_ir_resource_object ON ir_resource_events(object_id);

            CREATE TABLE IF NOT EXISTS ir_lock_events (
                id          INTEGER PRIMARY KEY,
                candidate_id TEXT DEFAULT '',
                lock_id     TEXT DEFAULT '',
                event_kind  TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                function    TEXT NOT NULL,
                path_id     TEXT DEFAULT '',
                held_before TEXT DEFAULT '',
                held_after  TEXT DEFAULT '',
                confidence  REAL DEFAULT 0.5
            );
            CREATE INDEX IF NOT EXISTS idx_ir_lock_candidate ON ir_lock_events(candidate_id);
            CREATE INDEX IF NOT EXISTS idx_ir_lock_id ON ir_lock_events(lock_id);

            CREATE TABLE IF NOT EXISTS ir_shared_accesses (
                id          INTEGER PRIMARY KEY,
                candidate_id TEXT DEFAULT '',
                object_id   TEXT DEFAULT '',
                field       TEXT DEFAULT '',
                access_kind TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                function    TEXT NOT NULL,
                guard_lock  TEXT DEFAULT '',
                thread_context TEXT DEFAULT '',
                confidence  REAL DEFAULT 0.5
            );
            CREATE INDEX IF NOT EXISTS idx_ir_shared_candidate ON ir_shared_accesses(candidate_id);
            CREATE INDEX IF NOT EXISTS idx_ir_shared_object ON ir_shared_accesses(object_id);

            CREATE TABLE IF NOT EXISTS ir_path_slices (
                id          INTEGER PRIMARY KEY,
                candidate_id TEXT NOT NULL UNIQUE,
                function    TEXT NOT NULL,
                source_stmt INTEGER,
                sink_stmt   INTEGER,
                path_summary TEXT DEFAULT '{}',
                guards      TEXT DEFAULT '[]',
                contradictions TEXT DEFAULT '[]',
                score_components TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_ir_path_func ON ir_path_slices(function);

            CREATE TABLE IF NOT EXISTS function_contracts (
                id          INTEGER PRIMARY KEY,
                function    TEXT NOT NULL UNIQUE,
                allocates   TEXT DEFAULT '[]',
                releases    TEXT DEFAULT '[]',
                transfers   TEXT DEFAULT '[]',
                borrows     TEXT DEFAULT '[]',
                locks       TEXT DEFAULT '[]',
                thread_effects TEXT DEFAULT '[]',
                return_semantics TEXT DEFAULT '',
                updated_at  REAL DEFAULT 0
            );
        """)
        # 写入 schema 版本
        c.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("schema_version", self.SCHEMA_VERSION),
        )
        c.commit()

        # 兼容旧 DB：补加 file_hash 列
        try:
            c.execute("ALTER TABLE translation_units ADD COLUMN file_hash TEXT DEFAULT ''")
            c.commit()
        except sqlite3.OperationalError:
            pass  # 列已存在

        # 兼容旧 DB：补加 svf_group 列
        try:
            c.execute("ALTER TABLE indirect_calls ADD COLUMN svf_group TEXT DEFAULT 'default'")
            c.execute("ALTER TABLE taint_signatures ADD COLUMN svf_group TEXT DEFAULT 'default'")
            c.commit()
        except sqlite3.OperationalError:
            pass

        # 兼容旧 DB：补加 callee_file 列
        try:
            c.execute("ALTER TABLE call_edges ADD COLUMN callee_file TEXT DEFAULT ''")
            c.commit()
        except sqlite3.OperationalError:
            pass

    # ── Translation Units ──

    def register_tu(self, file_path: str, mtime: float) -> int:
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO translation_units (file_path, last_modified, status) "
            "VALUES (?, ?, 'pending')",
            (file_path, mtime),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM translation_units WHERE file_path = ?", (file_path,)
        ).fetchone()
        return cast(int, row["id"])

    def register_tu_hash(self, file_path: str, file_hash: str) -> tuple:
        """注册 TU 并检查哈希。返回 (tu_id, changed: bool)。"""
        row = self._conn.execute(
            "SELECT id, file_hash, status FROM translation_units WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        if row:
            tu_id = row["id"]
            old_hash = row["file_hash"] or ""
            if old_hash == file_hash and row["status"] == "indexed":
                return (tu_id, False)  # 未变化
            # 哈希变了或状态非 indexed → 标记需要更新
            self._conn.execute(
                "UPDATE translation_units SET file_hash = ?, last_modified = ?, status = 'pending' WHERE id = ?",
                (file_hash, time.time(), tu_id),
            )
            self._conn.commit()
            return (tu_id, True)
        else:
            self._conn.execute(
                "INSERT INTO translation_units (file_path, file_hash, last_modified, status) "
                "VALUES (?, ?, ?, 'pending')",
                (file_path, file_hash, time.time()),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT id FROM translation_units WHERE file_path = ?", (file_path,),
            ).fetchone()
            return (row["id"], True)

    def purge_tu_data(self, tu_id: int):
        """清除某 TU 关联的所有提取数据。"""
        self._conn.execute("DELETE FROM functions WHERE tu_id = ?", (tu_id,))
        # call_edges 没有 tu_id，通过 caller_file 联动清除
        row = self._conn.execute(
            "SELECT file_path FROM translation_units WHERE id = ?", (tu_id,),
        ).fetchone()
        if row:
            fp = row["file_path"]
            path_variants = self._path_variants(fp)
            placeholders = ",".join("?" for _ in path_variants)
            self._conn.execute(
                f"DELETE FROM call_edges WHERE caller_file IN ({placeholders})",
                path_variants,
            )
            self._conn.execute(
                f"DELETE FROM include_edges WHERE source_file IN ({placeholders})",
                path_variants,
            )
            self._conn.execute(
                f"DELETE FROM global_variables WHERE file_path IN ({placeholders})",
                path_variants,
            )
            self._conn.execute(
                f"DELETE FROM macro_definitions WHERE file_path IN ({placeholders})",
                path_variants,
            )
            for table in (
                "ir_statements",
                "ir_resource_events",
                "ir_lock_events",
                "ir_shared_accesses",
            ):
                self._conn.execute(
                    f"DELETE FROM {table} WHERE file_path IN ({placeholders})",
                    path_variants,
                )
        self._conn.execute(
            "DELETE FROM type_members WHERE type_id IN "
            "(SELECT id FROM type_definitions WHERE tu_id = ?)", (tu_id,),
        )
        self._conn.execute("DELETE FROM type_definitions WHERE tu_id = ?", (tu_id,))
        self._conn.commit()

    @staticmethod
    def _path_variants(file_path: str) -> tuple[str, ...]:
        """Return canonical variants used by older and current extractor rows."""
        raw = str(file_path or "").replace("\\", "/")
        variants = {raw, raw.lstrip("/")}
        try:
            resolved = Path(file_path).resolve()
            variants.add(str(resolved))
            variants.add(resolved.as_posix())
            parts = list(resolved.parts)
            for marker in ("src", "include", "internal", "test", "zscope"):
                if marker in parts:
                    variants.add(Path(*parts[parts.index(marker):]).as_posix())
        except OSError:
            pass
        return tuple(sorted(item for item in variants if item))

    def mark_tu_indexed(self, tu_id: int):
        self._conn.execute(
            "UPDATE translation_units SET status = 'indexed', index_time = ? WHERE id = ?",
            (time.time(), tu_id),
        )
        self._conn.commit()

    def get_pending_tus(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, file_path, last_modified FROM translation_units WHERE status = 'pending'"
        ).fetchall()
        return [dict(r) for r in rows]

    # Inspection IR

    def upsert_ir_statement(self, file_path: str, line: int, function: str,
                            kind: str = "", normalized_code: str = "",
                            ast_kind: str = "", defs: str = "[]",
                            uses: str = "[]") -> int:
        self._conn.execute(
            "INSERT OR IGNORE INTO ir_statements "
            "(file_path, line, function, kind, normalized_code, ast_kind, defs, uses) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (file_path, line, function, kind, normalized_code, ast_kind, defs, uses),
        )
        row = self._conn.execute(
            "SELECT id FROM ir_statements WHERE file_path = ? AND line = ? "
            "AND function = ? AND normalized_code = ?",
            (file_path, line, function, normalized_code),
        ).fetchone()
        return int(row["id"]) if row else 0

    def insert_ir_resource_event(self, candidate_id: str, object_id: str,
                                 event_kind: str, api: str, file_path: str,
                                 line: int, function: str,
                                 owner_before: str = "", owner_after: str = "",
                                 condition: str = "", confidence: float = 0.5) -> int:
        cur = self._conn.execute(
            "INSERT INTO ir_resource_events "
            "(candidate_id, object_id, event_kind, api, file_path, line, function, "
            "owner_before, owner_after, condition, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (candidate_id, object_id, event_kind, api, file_path, line, function,
             owner_before, owner_after, condition, confidence),
        )
        return int(cur.lastrowid or 0)

    def insert_ir_lock_event(self, candidate_id: str, lock_id: str,
                             event_kind: str, file_path: str, line: int,
                             function: str, path_id: str = "",
                             held_before: str = "", held_after: str = "",
                             confidence: float = 0.5) -> int:
        cur = self._conn.execute(
            "INSERT INTO ir_lock_events "
            "(candidate_id, lock_id, event_kind, file_path, line, function, path_id, "
            "held_before, held_after, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (candidate_id, lock_id, event_kind, file_path, line, function, path_id,
             held_before, held_after, confidence),
        )
        return int(cur.lastrowid or 0)

    def insert_ir_shared_access(self, candidate_id: str, object_id: str,
                                field: str, access_kind: str, file_path: str,
                                line: int, function: str, guard_lock: str = "",
                                thread_context: str = "", confidence: float = 0.5) -> int:
        cur = self._conn.execute(
            "INSERT INTO ir_shared_accesses "
            "(candidate_id, object_id, field, access_kind, file_path, line, function, "
            "guard_lock, thread_context, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (candidate_id, object_id, field, access_kind, file_path, line, function,
             guard_lock, thread_context, confidence),
        )
        return int(cur.lastrowid or 0)

    def upsert_ir_path_slice(self, candidate_id: str, function: str,
                             source_stmt: int = 0, sink_stmt: int = 0,
                             path_summary: str = "{}", guards: str = "[]",
                             contradictions: str = "[]",
                             score_components: str = "{}") -> int:
        self._conn.execute(
            "INSERT OR REPLACE INTO ir_path_slices "
            "(candidate_id, function, source_stmt, sink_stmt, path_summary, guards, "
            "contradictions, score_components) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (candidate_id, function, source_stmt, sink_stmt, path_summary, guards,
             contradictions, score_components),
        )
        row = self._conn.execute(
            "SELECT id FROM ir_path_slices WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        return int(row["id"]) if row else 0

    def upsert_function_contract(self, function: str, allocates: str = "[]",
                                 releases: str = "[]", transfers: str = "[]",
                                 borrows: str = "[]", locks: str = "[]",
                                 thread_effects: str = "[]",
                                 return_semantics: str = "") -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO function_contracts "
            "(function, allocates, releases, transfers, borrows, locks, "
            "thread_effects, return_semantics, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (function, allocates, releases, transfers, borrows, locks,
             thread_effects, return_semantics, time.time()),
        )

    def get_ir_path_slice(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM ir_path_slices WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_all_tus(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM translation_units").fetchall()
        return [dict(r) for r in rows]

    # ── SVF Hash Cache ──

    def get_metadata(self, key: str) -> str:
        """Return a metadata value by key, or an empty string when absent."""
        row = self._conn.execute(
            "SELECT value FROM metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return row["value"] if row else ""

    def set_metadata(self, key: str, value: str) -> None:
        """Persist a metadata key/value pair."""
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    def get_svf_hash(self) -> str:
        """获取上次 SVF 分析时的源码聚合哈希。"""
        return self.get_metadata("svf_source_hash")

    def set_svf_hash(self, hash_value: str):
        """记录 SVF 源码聚合哈希。"""
        self.set_metadata("svf_source_hash", hash_value)

    def purge_svf_data(self, group: str = "default"):
        """清除 SVF 产生的间接调用和污点数据（按分组）。"""
        self._conn.execute("DELETE FROM indirect_calls WHERE svf_group = ?", (group,))
        self._conn.execute("DELETE FROM taint_signatures WHERE svf_group = ?", (group,))
        self._conn.commit()

    # ── Functions ──

    def insert_function(self, name: str, file_path: str, start_line: int, end_line: int,
                        signature: str = "", is_static: bool = False, is_inline: bool = False,
                        is_declaration: bool = False, tu_id: Optional[int] = None):
        self._conn.execute(
            "INSERT OR REPLACE INTO functions "
            "(name, file_path, start_line, end_line, signature, is_static, is_inline, is_declaration, tu_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, file_path, start_line, end_line, signature,
             int(is_static), int(is_inline), int(is_declaration), tu_id),
        )

    def insert_functions_batch(self, rows: List[tuple]):
        self._conn.executemany(
            "INSERT OR REPLACE INTO functions "
            "(name, file_path, start_line, end_line, signature, is_static, is_inline, is_declaration, tu_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    def get_function(self, name: str, file_path: str = "") -> Optional[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM functions WHERE name = ? AND is_declaration = 0 "
            "ORDER BY file_path, start_line",
            (name,),
        ).fetchall()
        if not rows:
            return None
        if file_path:
            for row in rows:
                if self._paths_match_hint(str(row["file_path"] or ""), file_path):
                    return dict(row)
        return dict(rows[0])

    def get_all_functions(self) -> Dict[str, Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, file_path, start_line, end_line, signature "
            "FROM functions WHERE is_declaration = 0 ORDER BY name, file_path, start_line"
        ).fetchall()
        index = {}
        for r in rows:
            name = r["name"]
            key = name
            if key in index:
                key = self._function_signature_key(name, r["signature"] or "")
            if key in index:
                key = f"{name}@{r['file_path']}:{r['start_line']}"
            index[key] = {
                "name": name,
                "file": r["file_path"],
                "start_line": r["start_line"],
                "end_line": r["end_line"],
                "signature": r["signature"] or f"{name}(...)",
            }
        return index

    @staticmethod
    def _function_signature_key(name: str, signature: str) -> str:
        if "(" not in signature or ")" not in signature:
            return name
        params = signature[signature.find("(") + 1 : signature.rfind(")")].strip()
        params = " ".join(params.split())
        return f"{name}({params})"

    # ── Type Definitions ──

    def insert_type(self, name: str, kind: str, file_path: str,
                    start_line: int, end_line: int,
                    full_definition: str = "", tu_id: Optional[int] = None) -> int:
        self._conn.execute(
            "INSERT OR REPLACE INTO type_definitions "
            "(name, kind, file_path, start_line, end_line, full_definition, tu_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, kind, file_path, start_line, end_line, full_definition, tu_id),
        )
        row = self._conn.execute(
            "SELECT id FROM type_definitions WHERE name=? AND kind=? AND file_path=?",
            (name, kind, file_path),
        ).fetchone()
        return row["id"] if row else -1

    def insert_type_member(self, type_id: int, member_name: str,
                           member_type: str = "", offset_idx: int = 0):
        self._conn.execute(
            "INSERT OR REPLACE INTO type_members "
            "(type_id, member_name, member_type, offset_idx) VALUES (?, ?, ?, ?)",
            (type_id, member_name, member_type, offset_idx),
        )

    def get_type_info(self, name: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM type_definitions WHERE name = ? LIMIT 1", (name,)
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        members = self._conn.execute(
            "SELECT member_name, member_type, offset_idx FROM type_members "
            "WHERE type_id = ? ORDER BY offset_idx", (row["id"],)
        ).fetchall()
        result["members"] = [dict(m) for m in members]
        return result

    # ── Call Edges ──

    def insert_call_edge(self, caller_name: str, caller_file: str,
                         callee_name: str, callee_file: str = "", call_line: int = 0,
                         call_type: str = "direct"):
        self._conn.execute(
            "INSERT OR IGNORE INTO call_edges "
            "(caller_name, caller_file, callee_name, callee_file, call_line, call_type) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (caller_name, caller_file, callee_name, callee_file, call_line, call_type),
        )

    def insert_call_edges_batch(self, rows: List[tuple]):
        self._conn.executemany(
            "INSERT OR IGNORE INTO call_edges "
            "(caller_name, caller_file, callee_name, callee_file, call_line, call_type) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        if callee_file:
            all_rows = self._conn.execute(
                "SELECT DISTINCT caller_name, caller_file, callee_file, call_line "
                "FROM call_edges WHERE callee_name = ?",
                (func_name,),
            ).fetchall()
            rows = [
                row
                for row in all_rows
                if self._paths_match_hint(str(row["callee_file"] or ""), callee_file)
            ][:limit]
        else:
            rows = self._conn.execute(
                "SELECT DISTINCT caller_name, caller_file, callee_file, call_line "
                "FROM call_edges WHERE callee_name = ? LIMIT ?",
                (func_name, limit),
            ).fetchall()
        return [{"name": r["caller_name"], "filename": r["caller_file"],
                 "callee_filename": r["callee_file"],
                 "lineNumber": r["call_line"]} for r in rows]

    def get_callees(
        self,
        func_name: str,
        limit: int = 30,
        caller_file: str = "",
    ) -> List[Dict[str, Any]]:
        if caller_file:
            all_rows = self._conn.execute(
                "SELECT DISTINCT callee_name, callee_file, call_line, call_type, caller_file "
                "FROM call_edges WHERE caller_name = ?",
                (func_name,),
            ).fetchall()
            rows = [
                row for row in all_rows
                if self._paths_match_hint(str(row["caller_file"] or ""), caller_file)
            ][:limit]
        else:
            rows = self._conn.execute(
                "SELECT DISTINCT callee_name, callee_file, call_line, call_type FROM call_edges "
                "WHERE caller_name = ? LIMIT ?",
                (func_name, limit),
            ).fetchall()
        return [{"name": r["callee_name"], "filename": r["callee_file"],
                 "lineNumber": r["call_line"], "call_type": r["call_type"]} for r in rows]

    @staticmethod
    def _paths_match_hint(stored_path: str, hint_path: str) -> bool:
        stored = str(stored_path or "").replace("\\", "/").strip()
        hint = str(hint_path or "").replace("\\", "/").strip()
        if not stored or not hint:
            return False
        stored = stored.lstrip("./")
        hint = hint.lstrip("./")
        return (
            stored == hint
            or stored.endswith(f"/{hint}")
            or hint.endswith(f"/{stored}")
        )

    def find_callers_without_callee(
        self,
        acquire_func: str,
        release_func: str,
        *,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT caller_name, caller_file, MIN(call_line) AS acquire_line
            FROM call_edges
            WHERE callee_name = ?
              AND NOT EXISTS (
                  SELECT 1 FROM call_edges rel
                  WHERE rel.caller_name = call_edges.caller_name
                    AND rel.caller_file = call_edges.caller_file
                    AND rel.callee_name = ?
              )
            GROUP BY caller_name, caller_file
            LIMIT ?
            """,
            (acquire_func, release_func, limit),
        ).fetchall()
        return [
            {
                "function": r["caller_name"],
                "file_path": r["caller_file"],
                "line": r["acquire_line"],
                "acquire_func": acquire_func,
                "release_func": release_func,
            }
            for r in rows
        ]

    # ── Header functions ──

    def get_header_functions(
        self,
        header_files: Optional[List[str]] = None,
        source_root: Optional[Path] = None,
    ) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, file_path, start_line FROM functions "
            "WHERE is_declaration = 1"
        ).fetchall()

        normalized_headers = (
            {
                self._normalize_source_relative_path(header, source_root)
                for header in header_files
            }
            if header_files
            else None
        )

        results = []
        for row in rows:
            filename = self._normalize_source_relative_path(row["file_path"], source_root)
            if normalized_headers is not None and filename not in normalized_headers:
                continue
            if normalized_headers is None and not filename.endswith((".h", ".hpp", ".ph", ".inc")):
                continue
            results.append(
                {
                    "name": row["name"],
                    "filename": filename,
                    "lineNumber": row["start_line"],
                }
            )
        return results

    @staticmethod
    def _normalize_source_relative_path(path: str, source_root: Optional[Path] = None) -> str:
        raw = Path(str(path))
        if source_root is not None:
            root = Path(source_root).resolve()
            candidate = raw if raw.is_absolute() else root / raw
            try:
                return candidate.resolve().relative_to(root).as_posix()
            except ValueError:
                pass
        return raw.as_posix()

    # ── Indirect Calls (SVF) ──

    def insert_indirect_call(self, caller: str, callee: str,
                             source: str = "svf-ander", confidence: float = 1.0,
                             call_file: str = "", call_line: int = 0,
                             svf_group: str = "default"):
        self._conn.execute(
            "INSERT OR IGNORE INTO indirect_calls "
            "(caller_name, callee_name, call_file, call_line, source, confidence, svf_group) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (caller, callee, call_file, call_line, source, confidence, svf_group),
        )

    def get_indirect_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT callee_name, source, confidence, svf_group, call_file, call_line FROM indirect_calls "
            "WHERE caller_name = ? ORDER BY confidence DESC LIMIT ?",
            (func_name, limit),
        ).fetchall()
        return [{"name": r["callee_name"], "source": r["source"],
                 "confidence": r["confidence"], "svf_group": r["svf_group"],
                 "call_file": r["call_file"], "call_line": r["call_line"]} for r in rows]

    def get_indirect_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT caller_name, source FROM indirect_calls "
            "WHERE callee_name = ? LIMIT ?",
            (func_name, limit),
        ).fetchall()
        return [{"name": r["caller_name"], "source": r["source"]} for r in rows]

    # ── Taint Signatures (SVF/Saber) ──

    def insert_taint_signature(self, source_func: str, sink_func: str, bug_type: str,
                               file_path: str = "", line: int = 0, tool: str = "saber",
                               svf_group: str = "default"):
        self._conn.execute(
            "INSERT OR IGNORE INTO taint_signatures "
            "(source_func, sink_func, bug_type, file_path, line, tool, svf_group) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source_func, sink_func, bug_type, file_path, line, tool, svf_group),
        )

    def get_taint_bugs(self, bug_type: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        if bug_type:
            rows = self._conn.execute(
                "SELECT * FROM taint_signatures WHERE bug_type LIKE ? LIMIT ?",
                (f"%{bug_type}%", limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM taint_signatures LIMIT ?", (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def find_function_at(self, file_path: str, line: int) -> Optional[Dict[str, Any]]:
        """通过 (file, line) 定位包含该行的函数——Clang/SVF 坐标缝合点。"""
        row = self._conn.execute(
            "SELECT * FROM functions WHERE file_path = ? "
            "AND start_line <= ? AND end_line >= ? AND is_declaration = 0 "
            "LIMIT 1",
            (file_path, line, line),
        ).fetchone()
        return dict(row) if row else None

    def get_enriched_taint_bugs(self, bug_type: str = "", func_name: str = "",
                                limit: int = 50) -> List[Dict[str, Any]]:
        """污点缺陷 JOIN 函数表，返回带 AST 上下文的富结果。"""
        where = ["1=1"]
        params: list = []
        if bug_type:
            where.append("t.bug_type LIKE ?")
            params.append(f"%{bug_type}%")
        if func_name:
            where.append("(t.source_func = ? OR f.name = ?)")
            params.extend([func_name, func_name])
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT t.*, f.name AS func_name, f.signature, "
            f"f.start_line AS func_start, f.end_line AS func_end "
            f"FROM taint_signatures t "
            f"LEFT JOIN functions f ON f.file_path = t.file_path "
            f"AND f.start_line <= t.line AND f.end_line >= t.line "
            f"AND f.is_declaration = 0 "
            f"WHERE {' AND '.join(where)} LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Utilities ──

    def commit(self):
        self._conn.commit()

    def stats(self) -> Dict[str, int]:
        result = {}
        for table in ("functions", "type_definitions", "call_edges",
                       "macro_definitions", "translation_units",
                       "indirect_calls", "taint_signatures",
                       "ir_statements", "ir_resource_events", "ir_lock_events",
                       "ir_shared_accesses", "ir_path_slices",
                       "function_contracts"):
            row = self._conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
            result[table] = row["cnt"]
        return result

    def close(self):
        with self._connections_lock:
            if self._closed:
                return
            self._closed = True
            connections = list(self._connections)
            self._connections.clear()

        for conn in connections:
            try:
                conn.commit()
            except sqlite3.Error as exc:
                logger.debug("KnowledgeDB commit during close failed: %s", exc)
            try:
                conn.close()
            except sqlite3.Error as exc:
                logger.debug("KnowledgeDB close failed: %s", exc)

        if hasattr(self._thread_local, "conn"):
            self._thread_local.conn = None
