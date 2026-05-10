"""
SQLite knowledge database for storing extracted code structure.
Persists function signatures, type definitions, call graph, macros, etc.
"""

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

logger = logging.getLogger(__name__)


class KnowledgeDB:
    """SQLite-backed code knowledge store."""

    SCHEMA_VERSION = "6"

    def __init__(self, db_path: str):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

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
            self._conn.execute("DELETE FROM call_edges WHERE caller_file = ?", (fp,))
            self._conn.execute("DELETE FROM include_edges WHERE source_file = ?", (fp,))
            self._conn.execute("DELETE FROM global_variables WHERE file_path = ?", (fp,))
            self._conn.execute("DELETE FROM macro_definitions WHERE file_path = ?", (fp,))
        self._conn.execute(
            "DELETE FROM type_members WHERE type_id IN "
            "(SELECT id FROM type_definitions WHERE tu_id = ?)", (tu_id,),
        )
        self._conn.execute("DELETE FROM type_definitions WHERE tu_id = ?", (tu_id,))
        self._conn.commit()

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

    def get_all_tus(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM translation_units").fetchall()
        return [dict(r) for r in rows]

    # ── SVF Hash Cache ──

    def get_svf_hash(self) -> str:
        """获取上次 SVF 分析时的源码聚合哈希。"""
        row = self._conn.execute(
            "SELECT value FROM metadata WHERE key = 'svf_source_hash'",
        ).fetchone()
        return row["value"] if row else ""

    def set_svf_hash(self, hash_value: str):
        """记录 SVF 源码聚合哈希。"""
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('svf_source_hash', ?)",
            (hash_value,),
        )
        self._conn.commit()

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

    def get_function(self, name: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM functions WHERE name = ? AND is_declaration = 0 LIMIT 1", (name,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_functions(self) -> Dict[str, Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, file_path, start_line, end_line, signature "
            "FROM functions WHERE is_declaration = 0"
        ).fetchall()
        index = {}
        for r in rows:
            index[r["name"]] = {
                "file": r["file_path"],
                "start_line": r["start_line"],
                "end_line": r["end_line"],
                "signature": r["signature"] or f"{r['name']}(...)",
            }
        return index

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

    def get_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT DISTINCT caller_name, caller_file, call_line "
            "FROM call_edges WHERE callee_name = ? LIMIT ?",
            (func_name, limit),
        ).fetchall()
        return [{"name": r["caller_name"], "filename": r["caller_file"],
                 "lineNumber": r["call_line"]} for r in rows]

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT DISTINCT callee_name, callee_file FROM call_edges "
            "WHERE caller_name = ? LIMIT ?",
            (func_name, limit),
        ).fetchall()
        return [{"name": r["callee_name"], "filename": r["callee_file"]} for r in rows]

    # ── Header functions ──

    def get_header_functions(self, header_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if header_files:
            placeholders = ",".join("?" for _ in header_files)
            rows = self._conn.execute(
                f"SELECT name, file_path, start_line FROM functions "
                f"WHERE is_declaration = 1 AND file_path IN ({placeholders})",
                header_files,
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT name, file_path, start_line FROM functions "
                "WHERE is_declaration = 1 AND file_path LIKE '%.h'"
            ).fetchall()
        return [{"name": r["name"], "filename": r["file_path"],
                 "lineNumber": r["start_line"]} for r in rows]

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
            "SELECT callee_name, source, confidence, svf_group FROM indirect_calls "
            "WHERE caller_name = ? ORDER BY confidence DESC LIMIT ?",
            (func_name, limit),
        ).fetchall()
        return [{"name": r["callee_name"], "source": r["source"],
                 "confidence": r["confidence"], "svf_group": r["svf_group"]} for r in rows]

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
                       "indirect_calls", "taint_signatures"):
            row = self._conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
            result[table] = row["cnt"]
        return result

    def close(self):
        self._conn.close()
