"""
SQLite knowledge database for storing extracted code structure.
Persists function signatures, type definitions, call graph, macros, etc.
"""

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, cast

logger = logging.getLogger(__name__)


class KnowledgeDB:
    """SQLite-backed code knowledge store."""

    SCHEMA_VERSION = "15"
    SUPPORTS_DEFERRED_TU_COMMITS = True
    DERIVED_INDEX_SYMBOL_CONTEXT = "function_symbol_context"
    DERIVED_INDEX_TYPE_REFS = "function_type_refs"
    DERIVED_INDEX_NAMES = (
        DERIVED_INDEX_SYMBOL_CONTEXT,
        DERIVED_INDEX_TYPE_REFS,
    )
    DERIVED_INDEX_METADATA_PREFIX = "derived_index_state:"
    _DERIVED_INDEX_ALIASES = {
        "function_symbol_context": DERIVED_INDEX_SYMBOL_CONTEXT,
        "function_symbol_refs": DERIVED_INDEX_SYMBOL_CONTEXT,
        "function_type_refs": DERIVED_INDEX_TYPE_REFS,
    }
    _DERIVED_INDEX_STATUSES = {"current", "dirty", "in_progress", "failed"}
    _DERIVED_SYMBOL_REF_STAGE = "zscope_stage_function_symbol_refs"
    _DERIVED_MACRO_REF_STAGE = "zscope_stage_function_macro_refs"
    _DERIVED_TYPE_REF_STAGE = "zscope_stage_function_type_refs"
    CALLGRAPH_READ_CONCURRENCY = 8
    TAINT_SIGNATURE_IDENTITY = (
        "source_func",
        "sink_func",
        "bug_type",
        "file_path",
        "line",
        "tool",
        "svf_group",
    )
    TAINT_REINDEX_REQUIRED_KEY = "taint_signatures_reindex_required"
    TAINT_REINDEX_REASON_KEY = "taint_signatures_reindex_reason"

    def __init__(self, db_path: str):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connections_lock = threading.RLock()
        self._query_cache_lock = threading.RLock()
        self._svf_materialization_lock = threading.RLock()
        self._derived_index_lock = threading.RLock()
        self._callgraph_read_semaphore = threading.BoundedSemaphore(self.CALLGRAPH_READ_CONCURRENCY)
        self._thread_local = threading.local()
        self._connections: List[sqlite3.Connection] = []
        self._callee_cache: Dict[Tuple[str, int, str], List[Dict[str, Any]]] = {}
        self._indirect_callee_cache: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        self._callgraph_cache_version = 0
        self._callee_cache_hits = 0
        self._callee_cache_misses = 0
        self._indirect_callee_cache_hits = 0
        self._indirect_callee_cache_misses = 0
        self._closed = False
        self._create_tables()

    @classmethod
    def _clone_query_rows(cls, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            {str(key): cls._clone_query_value(value) for key, value in row.items()} for row in rows
        ]

    @classmethod
    def _clone_query_value(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: cls._clone_query_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._clone_query_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(cls._clone_query_value(item) for item in value)
        return value

    def _invalidate_callgraph_query_cache(self) -> None:
        batch_active = bool(getattr(self._thread_local, "tu_facts_batch_active", False))
        if batch_active and bool(
            getattr(self._thread_local, "tu_facts_batch_callgraph_invalidated", False)
        ):
            return
        with self._query_cache_lock:
            self._callgraph_cache_version += 1
            self._callee_cache.clear()
            self._indirect_callee_cache.clear()
        if batch_active:
            self._thread_local.tu_facts_batch_callgraph_invalidated = True

    def callgraph_cache_stats(self) -> Dict[str, int]:
        with self._query_cache_lock:
            return {
                "version": self._callgraph_cache_version,
                "callee_hits": self._callee_cache_hits,
                "callee_misses": self._callee_cache_misses,
                "callee_size": len(self._callee_cache),
                "indirect_callee_hits": self._indirect_callee_cache_hits,
                "indirect_callee_misses": self._indirect_callee_cache_misses,
                "indirect_callee_size": len(self._indirect_callee_cache),
            }

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

    @classmethod
    def _taint_signature_identity_is_current(
        cls,
        conn: sqlite3.Connection,
    ) -> bool:
        """Return whether the table enforces the complete structural flow identity."""
        table_columns = {
            str(row["name"]): bool(row["notnull"])
            for row in conn.execute("PRAGMA table_info(taint_signatures)").fetchall()
        }
        if not all(table_columns.get(name, False) for name in cls.TAINT_SIGNATURE_IDENTITY):
            return False

        for index_row in conn.execute("PRAGMA index_list(taint_signatures)").fetchall():
            if not bool(index_row["unique"]):
                continue
            index_name = str(index_row["name"])
            quoted_index_name = '"' + index_name.replace('"', '""') + '"'
            columns = tuple(
                str(row["name"])
                for row in conn.execute(f"PRAGMA index_info({quoted_index_name})").fetchall()
            )
            if columns == cls.TAINT_SIGNATURE_IDENTITY:
                return True
        return False

    @classmethod
    def _migrate_taint_signature_identity(
        cls,
        conn: sqlite3.Connection,
    ) -> None:
        """Atomically widen taint identity and force one complete SVF refresh.

        The old location-only UNIQUE constraint may already have discarded distinct
        source/sink flows. Surviving rows are retained, but every cache layer that
        can skip SVF is invalidated so the missing flows are regenerated.
        """
        if cls._taint_signature_identity_is_current(conn):
            return

        replacement_table = "_taint_signatures_schema_v14"
        existing_replacement = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (replacement_table,),
        ).fetchone()
        if existing_replacement:
            raise RuntimeError(
                "Refusing taint-signature migration: temporary table "
                f"{replacement_table!r} already exists"
            )

        try:
            conn.execute("BEGIN IMMEDIATE")
            old_count = int(
                conn.execute("SELECT COUNT(*) AS count FROM taint_signatures").fetchone()["count"]
            )
            conn.execute(
                f"""
                CREATE TABLE "{replacement_table}" (
                    id          INTEGER PRIMARY KEY,
                    source_func TEXT NOT NULL DEFAULT '',
                    sink_func   TEXT NOT NULL DEFAULT '',
                    bug_type    TEXT NOT NULL,
                    file_path   TEXT NOT NULL DEFAULT '',
                    line        INTEGER NOT NULL DEFAULT 0,
                    tool        TEXT NOT NULL DEFAULT 'saber',
                    svf_group   TEXT NOT NULL DEFAULT 'default',
                    UNIQUE(
                        source_func,
                        sink_func,
                        bug_type,
                        file_path,
                        line,
                        tool,
                        svf_group
                    )
                )
                """
            )
            conn.execute(
                f"""
                INSERT OR IGNORE INTO "{replacement_table}"
                    (id, source_func, sink_func, bug_type, file_path, line, tool, svf_group)
                SELECT
                    id,
                    COALESCE(source_func, ''),
                    COALESCE(sink_func, ''),
                    bug_type,
                    COALESCE(file_path, ''),
                    COALESCE(line, 0),
                    COALESCE(tool, 'saber'),
                    COALESCE(svf_group, 'default')
                FROM taint_signatures
                ORDER BY id
                """
            )
            migrated_count = int(
                conn.execute(f'SELECT COUNT(*) AS count FROM "{replacement_table}"').fetchone()[
                    "count"
                ]
            )
            conn.execute("DROP TABLE taint_signatures")
            conn.execute(f'ALTER TABLE "{replacement_table}" RENAME TO taint_signatures')
            conn.execute("CREATE INDEX idx_taint_type ON taint_signatures(bug_type)")

            conn.execute(
                "DELETE FROM metadata "
                "WHERE key IN ('svf_source_hash', 'svf_artifact_hash') "
                "OR key LIKE 'svf_tool_status:%' "
                "OR key LIKE 'svf_db_import:%'"
            )
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (cls.TAINT_REINDEX_REQUIRED_KEY, "1"),
            )
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (
                    cls.TAINT_REINDEX_REASON_KEY,
                    "schema_v14_complete_taint_flow_identity",
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

        logger.warning(
            "[taint-migration] widened flow identity; preserved=%d collapsed_duplicates=%d; "
            "invalidated SVF caches and marked reindex required",
            migrated_count,
            old_count - migrated_count,
        )

    def _create_tables(self):
        c = self._conn
        c.executescript(
            """
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
            CREATE INDEX IF NOT EXISTS idx_functions_tu ON functions(tu_id);

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
            CREATE INDEX IF NOT EXISTS idx_types_tu ON type_definitions(tu_id);

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
                callee_kind TEXT DEFAULT 'unknown',
                callee_signature TEXT DEFAULT '',
                UNIQUE(caller_name, caller_file, callee_name, callee_file, call_line)
            );
            CREATE INDEX IF NOT EXISTS idx_call_caller ON call_edges(caller_name);
            CREATE INDEX IF NOT EXISTS idx_call_callee ON call_edges(callee_name);
            CREATE INDEX IF NOT EXISTS idx_call_caller_file ON call_edges(caller_file);

            CREATE TABLE IF NOT EXISTS macro_definitions (
                id          INTEGER PRIMARY KEY,
                macro_index_name TEXT NOT NULL DEFAULT '',
                name        TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                start_line  INTEGER NOT NULL DEFAULT 0,
                end_line    INTEGER NOT NULL DEFAULT 0,
                definition  TEXT,
                is_function_like INTEGER DEFAULT 0,
                UNIQUE(name, file_path, line),
                UNIQUE(macro_index_name)
            );
            CREATE INDEX IF NOT EXISTS idx_macros_name ON macro_definitions(name);
            CREATE INDEX IF NOT EXISTS idx_macros_file ON macro_definitions(file_path);

            CREATE TABLE IF NOT EXISTS global_variables (
                id          INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                type_str    TEXT,
                file_path   TEXT NOT NULL,
                line        INTEGER NOT NULL,
                is_extern   INTEGER DEFAULT 0,
                storage_class TEXT DEFAULT 'unknown',
                qualifiers  TEXT DEFAULT '',
                initializer TEXT DEFAULT '',
                definition_kind TEXT DEFAULT 'unknown',
                UNIQUE(name, file_path)
            );
            CREATE INDEX IF NOT EXISTS idx_globals_file ON global_variables(file_path);

            CREATE TABLE IF NOT EXISTS function_symbol_refs (
                id          INTEGER PRIMARY KEY,
                function_name TEXT NOT NULL,
                function_file TEXT NOT NULL,
                symbol_name TEXT NOT NULL,
                symbol_kind TEXT NOT NULL,
                symbol_file TEXT DEFAULT '',
                reference_line INTEGER DEFAULT 0,
                access_kind TEXT DEFAULT 'unknown',
                UNIQUE(
                    function_name,
                    function_file,
                    symbol_name,
                    symbol_kind,
                    symbol_file,
                    reference_line
                )
            );
            CREATE INDEX IF NOT EXISTS idx_symbol_refs_function
                ON function_symbol_refs(function_name, function_file);
            CREATE INDEX IF NOT EXISTS idx_symbol_refs_symbol
                ON function_symbol_refs(symbol_name, symbol_kind);
            CREATE INDEX IF NOT EXISTS idx_symbol_refs_function_file
                ON function_symbol_refs(function_file);
            CREATE INDEX IF NOT EXISTS idx_symbol_refs_symbol_file
                ON function_symbol_refs(symbol_file);

            CREATE TABLE IF NOT EXISTS function_macro_refs (
                id          INTEGER PRIMARY KEY,
                function_id INTEGER NOT NULL,
                macro_id    INTEGER NOT NULL,
                reference_line INTEGER NOT NULL,
                UNIQUE(function_id, macro_id, reference_line),
                FOREIGN KEY(function_id) REFERENCES functions(id),
                FOREIGN KEY(macro_id) REFERENCES macro_definitions(id)
            );
            CREATE INDEX IF NOT EXISTS idx_function_macro_refs_function
                ON function_macro_refs(function_id);
            CREATE INDEX IF NOT EXISTS idx_function_macro_refs_macro
                ON function_macro_refs(macro_id);

            CREATE TABLE IF NOT EXISTS function_type_refs (
                id          INTEGER PRIMARY KEY,
                function_id INTEGER NOT NULL,
                type_id     INTEGER,
                type_index_name TEXT NOT NULL DEFAULT '',
                referenced_name TEXT NOT NULL,
                reference_file TEXT NOT NULL,
                reference_line INTEGER NOT NULL,
                reference_kind TEXT NOT NULL,
                resolution_reason TEXT DEFAULT '',
                UNIQUE(
                    function_id,
                    referenced_name,
                    type_index_name,
                    reference_line,
                    reference_kind
                ),
                FOREIGN KEY(function_id) REFERENCES functions(id),
                FOREIGN KEY(type_id) REFERENCES type_definitions(id)
            );
            CREATE INDEX IF NOT EXISTS idx_function_type_refs_function
                ON function_type_refs(function_id);
            CREATE INDEX IF NOT EXISTS idx_function_type_refs_type
                ON function_type_refs(type_id);
            CREATE INDEX IF NOT EXISTS idx_function_type_refs_name
                ON function_type_refs(referenced_name);

            CREATE TABLE IF NOT EXISTS function_type_ref_state (
                function_id INTEGER PRIMARY KEY,
                identity TEXT NOT NULL,
                context TEXT NOT NULL,
                file_path TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                generation TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                retry_count INTEGER NOT NULL DEFAULT 0,
                retry_after REAL NOT NULL DEFAULT 0,
                FOREIGN KEY(function_id) REFERENCES functions(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_type_ref_pending
                ON function_type_ref_state(generation, status, file_path, start_line, function_id);
            CREATE INDEX IF NOT EXISTS idx_type_ref_retry
                ON function_type_ref_state(generation, status, retry_after);

            CREATE TABLE IF NOT EXISTS include_edges (
                id          INTEGER PRIMARY KEY,
                source_file TEXT NOT NULL,
                included_file TEXT NOT NULL,
                line        INTEGER,
                is_system   INTEGER DEFAULT 0,
                UNIQUE(source_file, included_file, line)
            );
            CREATE INDEX IF NOT EXISTS idx_include_source ON include_edges(source_file);
            CREATE INDEX IF NOT EXISTS idx_include_included ON include_edges(included_file);

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
                callsite_id TEXT DEFAULT '',
                pointer_symbol TEXT DEFAULT '',
                pointer_kind TEXT DEFAULT 'unknown',
                pointer_type TEXT DEFAULT '',
                pointer_signature TEXT DEFAULT '',
                callsite_expression TEXT DEFAULT '',
                call_guard  TEXT DEFAULT '',
                source      TEXT DEFAULT 'svf-ander',
                confidence  REAL DEFAULT 1.0,
                svf_group   TEXT DEFAULT 'default',
                UNIQUE(caller_name, callee_name, call_file, call_line, callsite_id,
                       pointer_symbol, source, svf_group)
            );
            CREATE INDEX IF NOT EXISTS idx_ic_caller ON indirect_calls(caller_name);
            CREATE INDEX IF NOT EXISTS idx_ic_callee ON indirect_calls(callee_name);
            CREATE INDEX IF NOT EXISTS idx_ic_file_line ON indirect_calls(call_file, call_line);

            CREATE TABLE IF NOT EXISTS taint_signatures (
                id          INTEGER PRIMARY KEY,
                source_func TEXT NOT NULL DEFAULT '',
                sink_func   TEXT NOT NULL DEFAULT '',
                bug_type    TEXT NOT NULL,
                file_path   TEXT NOT NULL DEFAULT '',
                line        INTEGER NOT NULL DEFAULT 0,
                tool        TEXT NOT NULL DEFAULT 'saber',
                svf_group   TEXT NOT NULL DEFAULT 'default',
                UNIQUE(
                    source_func,
                    sink_func,
                    bug_type,
                    file_path,
                    line,
                    tool,
                    svf_group
                )
            );
            CREATE INDEX IF NOT EXISTS idx_taint_type ON taint_signatures(bug_type);
            CREATE INDEX IF NOT EXISTS idx_taint_file ON taint_signatures(file_path);

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
            CREATE INDEX IF NOT EXISTS idx_ir_cfg_from_stmt ON ir_cfg_edges(from_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_cfg_to_stmt ON ir_cfg_edges(to_stmt);

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
            CREATE INDEX IF NOT EXISTS idx_ir_du_def_stmt ON ir_def_use_edges(def_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_du_use_stmt ON ir_def_use_edges(use_stmt);

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
            CREATE INDEX IF NOT EXISTS idx_ir_resource_file ON ir_resource_events(file_path);

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
            CREATE INDEX IF NOT EXISTS idx_ir_lock_file ON ir_lock_events(file_path);

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
            CREATE INDEX IF NOT EXISTS idx_ir_shared_file ON ir_shared_accesses(file_path);

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
            CREATE INDEX IF NOT EXISTS idx_ir_path_source_stmt ON ir_path_slices(source_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_path_sink_stmt ON ir_path_slices(sink_stmt);

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
        """
        )
        c.commit()

        c.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('svf_db_generation', '0')")
        c.commit()

        # 兼容旧 DB：补加 file_hash 列
        try:
            c.execute("ALTER TABLE translation_units ADD COLUMN file_hash TEXT DEFAULT ''")
            c.commit()
        except sqlite3.OperationalError:
            pass  # 列已存在

        # 兼容旧 DB：补加 svf_group 列
        for column_sql in (
            "ALTER TABLE indirect_calls ADD COLUMN svf_group TEXT DEFAULT 'default'",
            "ALTER TABLE taint_signatures ADD COLUMN svf_group TEXT DEFAULT 'default'",
        ):
            try:
                c.execute(column_sql)
                c.commit()
            except sqlite3.OperationalError:
                pass

        # 兼容旧 DB：历史 indirect_calls 的唯一键按函数聚合，会丢失同一 caller
        # 中多个函数指针调用点的候选事实。重建表以加入 callsite identity；旧行
        # 使用空 identity 保留，绝不根据名称猜测 pointer/callsite 信息。
        indirect_columns = {
            str(row["name"]) for row in c.execute("PRAGMA table_info(indirect_calls)").fetchall()
        }
        required_indirect_columns = {
            "callsite_id",
            "pointer_symbol",
            "pointer_kind",
            "pointer_type",
            "pointer_signature",
            "callsite_expression",
            "call_guard",
        }
        if not required_indirect_columns.issubset(indirect_columns):
            c.executescript(
                """
                CREATE TABLE indirect_calls_v12 (
                    id INTEGER PRIMARY KEY,
                    caller_name TEXT NOT NULL,
                    callee_name TEXT NOT NULL,
                    call_file TEXT DEFAULT '',
                    call_line INTEGER DEFAULT 0,
                    callsite_id TEXT DEFAULT '',
                    pointer_symbol TEXT DEFAULT '',
                    pointer_kind TEXT DEFAULT 'unknown',
                    pointer_type TEXT DEFAULT '',
                    pointer_signature TEXT DEFAULT '',
                    callsite_expression TEXT DEFAULT '',
                    call_guard TEXT DEFAULT '',
                    source TEXT DEFAULT 'svf-ander',
                    confidence REAL DEFAULT 1.0,
                    svf_group TEXT DEFAULT 'default',
                    UNIQUE(caller_name, callee_name, call_file, call_line, callsite_id,
                           pointer_symbol, source, svf_group)
                );
                INSERT INTO indirect_calls_v12 (
                    id, caller_name, callee_name, call_file, call_line, source,
                    confidence, svf_group
                )
                SELECT id, caller_name, callee_name, call_file, call_line, source,
                       confidence, svf_group
                FROM indirect_calls;
                DROP TABLE indirect_calls;
                ALTER TABLE indirect_calls_v12 RENAME TO indirect_calls;
                CREATE INDEX IF NOT EXISTS idx_ic_caller ON indirect_calls(caller_name);
                CREATE INDEX IF NOT EXISTS idx_ic_callee ON indirect_calls(callee_name);
                CREATE INDEX IF NOT EXISTS idx_ic_file_line ON indirect_calls(call_file, call_line);
                CREATE INDEX IF NOT EXISTS idx_ic_callsite
                    ON indirect_calls(caller_name, callsite_id);
                """
            )
            c.commit()
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_ic_callsite "
            "ON indirect_calls(caller_name, callsite_id)"
        )
        c.commit()

        # 兼容旧 DB：补加 callee_file 列
        try:
            c.execute("ALTER TABLE call_edges ADD COLUMN callee_file TEXT DEFAULT ''")
            c.commit()
        except sqlite3.OperationalError:
            pass

        # 兼容旧 DB：历史边不能安全假定为普通函数调用。
        try:
            c.execute("ALTER TABLE call_edges ADD COLUMN callee_kind TEXT DEFAULT 'unknown'")
            c.commit()
        except sqlite3.OperationalError:
            pass

        try:
            c.execute("ALTER TABLE call_edges ADD COLUMN callee_signature TEXT DEFAULT ''")
            c.commit()
        except sqlite3.OperationalError:
            pass

        # Schema v14 widens the taint identity after the v12/v13 call-graph
        # migrations. Older identities may have collapsed distinct flows, so
        # this migration also invalidates every reusable SVF materialization.
        self._migrate_taint_signature_identity(c)

        for column_sql in (
            "ALTER TABLE global_variables ADD COLUMN storage_class TEXT DEFAULT 'unknown'",
            "ALTER TABLE global_variables ADD COLUMN qualifiers TEXT DEFAULT ''",
            "ALTER TABLE global_variables ADD COLUMN initializer TEXT DEFAULT ''",
            "ALTER TABLE global_variables ADD COLUMN definition_kind TEXT DEFAULT 'unknown'",
        ):
            try:
                c.execute(column_sql)
                c.commit()
            except sqlite3.OperationalError:
                pass

        for column_sql in (
            "ALTER TABLE macro_definitions ADD COLUMN macro_index_name TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE macro_definitions ADD COLUMN start_line INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE macro_definitions ADD COLUMN end_line INTEGER NOT NULL DEFAULT 0",
        ):
            try:
                c.execute(column_sql)
                c.commit()
            except sqlite3.OperationalError:
                pass

        macro_rows = c.execute(
            "SELECT id, name, file_path, line, start_line, end_line, definition, "
            "macro_index_name FROM macro_definitions"
        ).fetchall()
        migrated_macros = 0
        for row in macro_rows:
            start_line = int(row["start_line"] or row["line"] or 1)
            definition_lines = str(row["definition"] or "").splitlines()
            end_line = int(row["end_line"] or 0)
            if end_line < start_line:
                end_line = start_line + max(1, len(definition_lines)) - 1
            macro_index_name = str(row["macro_index_name"] or "").strip()
            if not macro_index_name:
                macro_index_name = (
                    f"{str(row['name'] or '')}@{str(row['file_path'] or '')}:"
                    f"{start_line}-{end_line}"
                )
            c.execute(
                "UPDATE macro_definitions SET line = ?, start_line = ?, end_line = ?, "
                "macro_index_name = ? WHERE id = ?",
                (start_line, start_line, end_line, macro_index_name, int(row["id"])),
            )
            migrated_macros += 1
        try:
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_macros_index_name "
                "ON macro_definitions(macro_index_name)"
            )
        except sqlite3.IntegrityError as exc:
            logger.error(
                "[macro-migration] failed total=%d migrated=%d collisions=1 error=%s",
                len(macro_rows),
                migrated_macros,
                exc,
            )
            raise
        logger.info(
            "[macro-migration] completed total=%d migrated=%d collisions=0 failed=0",
            len(macro_rows),
            migrated_macros,
        )
        # Schema-v14 performance indexes are additive: keep the schema version stable
        # while ensuring existing v14 databases receive the same purge/include indexes
        # as newly-created databases. This runs after compatibility columns/tables are
        # present (notably call_edges.callee_file and the taint table replacement).
        c.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_functions_tu ON functions(tu_id);
            CREATE INDEX IF NOT EXISTS idx_types_tu ON type_definitions(tu_id);
            CREATE INDEX IF NOT EXISTS idx_call_caller_file ON call_edges(caller_file);
            CREATE INDEX IF NOT EXISTS idx_call_callee_file ON call_edges(callee_file);
            CREATE INDEX IF NOT EXISTS idx_macros_file ON macro_definitions(file_path);
            CREATE INDEX IF NOT EXISTS idx_globals_file ON global_variables(file_path);
            CREATE INDEX IF NOT EXISTS idx_symbol_refs_function_file
                ON function_symbol_refs(function_file);
            CREATE INDEX IF NOT EXISTS idx_symbol_refs_symbol_file
                ON function_symbol_refs(symbol_file);
            CREATE INDEX IF NOT EXISTS idx_include_source ON include_edges(source_file);
            CREATE INDEX IF NOT EXISTS idx_include_included ON include_edges(included_file);
            CREATE INDEX IF NOT EXISTS idx_taint_file ON taint_signatures(file_path);
            CREATE INDEX IF NOT EXISTS idx_ir_cfg_from_stmt ON ir_cfg_edges(from_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_cfg_to_stmt ON ir_cfg_edges(to_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_du_def_stmt ON ir_def_use_edges(def_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_du_use_stmt ON ir_def_use_edges(use_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_resource_file ON ir_resource_events(file_path);
            CREATE INDEX IF NOT EXISTS idx_ir_lock_file ON ir_lock_events(file_path);
            CREATE INDEX IF NOT EXISTS idx_ir_shared_file ON ir_shared_accesses(file_path);
            CREATE INDEX IF NOT EXISTS idx_ir_path_source_stmt ON ir_path_slices(source_stmt);
            CREATE INDEX IF NOT EXISTS idx_ir_path_sink_stmt ON ir_path_slices(sink_stmt);
            """
        )
        c.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("schema_version", self.SCHEMA_VERSION),
        )
        c.commit()

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

    def register_tu_hash(
        self,
        file_path: str,
        file_hash: str,
        *,
        commit: bool = True,
    ) -> tuple:
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
            if old_hash != file_hash:
                self.mark_derived_indexes_dirty(
                    reason="translation_unit_hash_changed",
                    commit=False,
                )
            if commit:
                self._conn.commit()
            return (tu_id, True)
        else:
            self._conn.execute(
                "INSERT INTO translation_units (file_path, file_hash, last_modified, status) "
                "VALUES (?, ?, ?, 'pending')",
                (file_path, file_hash, time.time()),
            )
            self.mark_derived_indexes_dirty(
                reason="translation_unit_added",
                commit=False,
            )
            if commit:
                self._conn.commit()
            row = self._conn.execute(
                "SELECT id FROM translation_units WHERE file_path = ?",
                (file_path,),
            ).fetchone()
            return (row["id"], True)

    def get_tu_delete_impact(self, tu_id: int) -> Dict[str, Any]:
        """Return files and symbols affected by deleting one translation unit."""
        row = self._conn.execute(
            "SELECT file_path FROM translation_units WHERE id = ?",
            (tu_id,),
        ).fetchone()
        if not row:
            return {"deleted_paths": [], "deleted_symbols": [], "related_files": []}

        fp = str(row["file_path"] or "")
        path_variants = self._path_variants(fp)
        placeholders = ",".join("?" for _ in path_variants)
        symbols = {
            str(r["name"])
            for r in self._conn.execute(
                "SELECT DISTINCT name FROM functions WHERE tu_id = ?",
                (tu_id,),
            ).fetchall()
            if str(r["name"] or "")
        }

        related: set[str] = set()
        type_ref_rows = self._conn.execute(
            "SELECT DISTINCT f.file_path FROM function_type_refs r "
            "JOIN functions f ON f.id = r.function_id "
            "WHERE r.type_id IN (SELECT id FROM type_definitions WHERE tu_id = ?)",
            (tu_id,),
        ).fetchall()
        related.update(str(r["file_path"] or "") for r in type_ref_rows)
        if path_variants:
            macro_ref_rows = self._conn.execute(
                "SELECT DISTINCT f.file_path FROM function_macro_refs r "
                "JOIN functions f ON f.id = r.function_id "
                "JOIN macro_definitions m ON m.id = r.macro_id "
                f"WHERE m.file_path IN ({placeholders})",
                path_variants,
            ).fetchall()
            related.update(str(r["file_path"] or "") for r in macro_ref_rows)
            incoming = self._conn.execute(
                f"SELECT DISTINCT caller_file FROM call_edges "
                f"WHERE callee_file IN ({placeholders})",
                path_variants,
            ).fetchall()
            related.update(str(r["caller_file"] or "") for r in incoming)

        if symbols:
            sorted_symbols = sorted(symbols)
            for offset in range(0, len(sorted_symbols), 50):
                symbol_chunk = sorted_symbols[offset : offset + 50]
                symbol_placeholders = ",".join("?" for _ in symbol_chunk)
                incoming_by_name = self._conn.execute(
                    "SELECT DISTINCT caller_file FROM call_edges "
                    f"WHERE callee_name IN ({symbol_placeholders})",
                    tuple(symbol_chunk),
                ).fetchall()
                related.update(str(r["caller_file"] or "") for r in incoming_by_name)

        include_hints = set(path_variants)
        deleted_name = Path(fp).name
        if deleted_name:
            include_hints.add(deleted_name)
        indexed_hint_set: set[str] = set()
        for value in include_hints:
            raw_hint = str(value or "").replace("\\", "/")
            if not raw_hint:
                continue
            variants = {raw_hint, raw_hint.lstrip("./")}
            indexed_hint_set.update(variants)
            indexed_hint_set.update(item.replace("/", "\\") for item in variants)
        indexed_hints = sorted(indexed_hint_set)
        for hint_chunk_start in range(0, len(indexed_hints), 50):
            hint_chunk = indexed_hints[hint_chunk_start : hint_chunk_start + 50]
            hint_placeholders = ",".join("?" for _ in hint_chunk)
            include_rows = self._conn.execute(
                "SELECT DISTINCT source_file FROM include_edges "
                f"WHERE included_file IN ({hint_placeholders})",
                tuple(hint_chunk),
            ).fetchall()
            related.update(str(row["source_file"] or "") for row in include_rows)

        related = {item for item in related if item and item not in path_variants}
        return {
            "deleted_paths": list(path_variants),
            "deleted_symbols": sorted(symbols),
            "related_files": sorted(related),
        }

    def delete_tu(self, tu_id: int, *, commit: bool = True) -> Dict[str, Any]:
        """Delete a translation unit and all file-owned facts from the database."""
        impact = self.get_tu_delete_impact(tu_id)
        self.purge_tu_data(tu_id, purge_incoming_refs=True, commit=False)
        self._conn.execute("DELETE FROM translation_units WHERE id = ?", (tu_id,))
        if commit:
            self._conn.commit()
        return impact

    def purge_tu_data(
        self,
        tu_id: int,
        purge_incoming_refs: bool = False,
        *,
        commit: bool = True,
    ):
        """清除某 TU 关联的所有提取数据。"""
        self._invalidate_callgraph_query_cache()
        batch_active = bool(getattr(self._thread_local, "tu_facts_batch_active", False))
        batch_already_dirty = bool(
            getattr(self._thread_local, "tu_facts_batch_derived_dirty", False)
        )
        if not batch_active or not batch_already_dirty:
            self.mark_derived_indexes_dirty(
                reason="translation_unit_purged",
                commit=False,
            )
            if batch_active:
                self._thread_local.tu_facts_batch_derived_dirty = True
        deleted_svf_rows = 0
        self._conn.execute(
            "DELETE FROM function_type_ref_state WHERE function_id IN "
            "(SELECT id FROM functions WHERE tu_id = ?)",
            (tu_id,),
        )
        self._conn.execute(
            "DELETE FROM function_type_refs WHERE function_id IN "
            "(SELECT id FROM functions WHERE tu_id = ?)",
            (tu_id,),
        )
        self._conn.execute(
            "DELETE FROM function_macro_refs WHERE function_id IN "
            "(SELECT id FROM functions WHERE tu_id = ?)",
            (tu_id,),
        )
        self._conn.execute("DELETE FROM functions WHERE tu_id = ?", (tu_id,))
        # call_edges 没有 tu_id，通过 caller_file 联动清除
        row = self._conn.execute(
            "SELECT file_path FROM translation_units WHERE id = ?",
            (tu_id,),
        ).fetchone()
        if row:
            fp = row["file_path"]
            path_variants = self._path_variants(fp)
            placeholders = ",".join("?" for _ in path_variants)
            stmt_id_stage = "zscope_purge_statement_ids"
            self._conn.execute(
                f"CREATE TEMP TABLE IF NOT EXISTS {stmt_id_stage} ("
                "id INTEGER PRIMARY KEY, function TEXT NOT NULL DEFAULT '')"
            )
            self._conn.execute(f"DELETE FROM {stmt_id_stage}")
            self._conn.execute(
                f"INSERT INTO {stmt_id_stage} (id, function) "
                "SELECT id, function FROM ir_statements "
                f"WHERE file_path IN ({placeholders})",
                path_variants,
            )
            self._conn.execute(
                f"DELETE FROM call_edges WHERE caller_file IN ({placeholders})",
                path_variants,
            )
            if purge_incoming_refs:
                self._conn.execute(
                    f"DELETE FROM call_edges WHERE callee_file IN ({placeholders})",
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
                f"DELETE FROM function_symbol_refs WHERE function_file IN ({placeholders})",
                path_variants,
            )
            if purge_incoming_refs:
                self._conn.execute(
                    f"DELETE FROM function_symbol_refs WHERE symbol_file IN ({placeholders})",
                    path_variants,
                )
                self._conn.execute(
                    "DELETE FROM function_macro_refs WHERE macro_id IN "
                    f"(SELECT id FROM macro_definitions WHERE file_path IN ({placeholders}))",
                    path_variants,
                )
            self._conn.execute(
                f"DELETE FROM macro_definitions WHERE file_path IN ({placeholders})",
                path_variants,
            )
            cursor = self._conn.execute(
                f"DELETE FROM indirect_calls WHERE call_file IN ({placeholders})",
                path_variants,
            )
            deleted_svf_rows += max(0, int(cursor.rowcount or 0))
            cursor = self._conn.execute(
                f"DELETE FROM taint_signatures WHERE file_path IN ({placeholders})",
                path_variants,
            )
            deleted_svf_rows += max(0, int(cursor.rowcount or 0))
            self._conn.execute(
                f"DELETE FROM ir_cfg_edges WHERE from_stmt IN (SELECT id FROM {stmt_id_stage}) "
                f"OR to_stmt IN (SELECT id FROM {stmt_id_stage})"
            )
            self._conn.execute(
                f"DELETE FROM ir_def_use_edges WHERE def_stmt IN (SELECT id FROM {stmt_id_stage}) "
                f"OR use_stmt IN (SELECT id FROM {stmt_id_stage})"
            )
            self._conn.execute(
                f"DELETE FROM ir_path_slices WHERE source_stmt IN (SELECT id FROM {stmt_id_stage}) "
                f"OR sink_stmt IN (SELECT id FROM {stmt_id_stage})"
            )
            self._conn.execute(
                f"DELETE FROM ir_cfg_edges WHERE function IN "
                f"(SELECT DISTINCT function FROM {stmt_id_stage} WHERE function != '')"
            )
            self._conn.execute(
                f"DELETE FROM ir_path_slices WHERE function IN "
                f"(SELECT DISTINCT function FROM {stmt_id_stage} WHERE function != '')"
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
            self._conn.execute(f"DELETE FROM {stmt_id_stage}")
        self._conn.execute(
            "DELETE FROM type_members WHERE type_id IN "
            "(SELECT id FROM type_definitions WHERE tu_id = ?)",
            (tu_id,),
        )
        self._conn.execute(
            "DELETE FROM function_type_refs WHERE type_id IN "
            "(SELECT id FROM type_definitions WHERE tu_id = ?)",
            (tu_id,),
        )
        self._conn.execute("DELETE FROM type_definitions WHERE tu_id = ?", (tu_id,))
        if deleted_svf_rows:
            generation = self.get_svf_db_generation() + 1
            self._set_metadata_uncommitted("svf_db_generation", str(generation))
            logger.info(
                "SVF materialization invalidated: event=tu_purge tu_id=%s "
                "deleted_rows=%d db_generation=%d",
                tu_id,
                deleted_svf_rows,
                generation,
            )
        if commit:
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
                    variants.add(Path(*parts[parts.index(marker) :]).as_posix())
        except OSError:
            pass
        return tuple(sorted(item for item in variants if item))

    def mark_tu_indexed(self, tu_id: int, *, commit: bool = True):
        self._conn.execute(
            "UPDATE translation_units SET status = 'indexed', index_time = ? WHERE id = ?",
            (time.time(), tu_id),
        )
        if commit:
            self._conn.commit()

    @contextmanager
    def replace_tu_facts_transaction(self, tu_id: int) -> Iterator[None]:
        """Atomically replace all base facts owned by one translation unit.

        The caller writes the replacement facts inside this context without
        committing. Until the savepoint is released, readers retain the last
        committed facts; any exception or process interruption rolls the purge
        and partial replacement back together.
        """
        conn = self._conn
        savepoint = f"replace_tu_facts_{threading.get_ident()}_{int(tu_id)}"
        savepoint_active = False
        batch_dirty_before = bool(
            getattr(self._thread_local, "tu_facts_batch_derived_dirty", False)
        )
        try:
            conn.execute(f"SAVEPOINT {savepoint}")
            savepoint_active = True
            self.purge_tu_data(tu_id, commit=False)
            yield
            self.mark_tu_indexed(tu_id, commit=False)
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            savepoint_active = False
            if not bool(getattr(self._thread_local, "tu_facts_batch_active", False)):
                conn.commit()
        except BaseException:
            if savepoint_active:
                conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                if bool(getattr(self._thread_local, "tu_facts_batch_active", False)):
                    self._thread_local.tu_facts_batch_derived_dirty = batch_dirty_before
            else:
                conn.rollback()
            raise

    @contextmanager
    def replace_tu_facts_batch_transaction(self) -> Iterator[None]:
        """Publish multiple TU replacements in one transaction.

        Each :meth:`replace_tu_facts_transaction` nested inside this context keeps
        its own savepoint. A caller may catch one TU failure and continue; an
        exception escaping this outer context rolls the whole batch back.
        """
        conn = self._conn
        if bool(getattr(self._thread_local, "tu_facts_batch_active", False)):
            raise RuntimeError("nested TU facts batch transactions are not supported")
        if conn.in_transaction:
            raise RuntimeError("TU facts batch transaction requires a clean connection")
        self._thread_local.tu_facts_batch_active = True
        self._thread_local.tu_facts_batch_derived_dirty = False
        self._thread_local.tu_facts_batch_callgraph_invalidated = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                conn.rollback()
                raise
            else:
                conn.commit()
        finally:
            self._thread_local.tu_facts_batch_active = False
            self._thread_local.tu_facts_batch_derived_dirty = False
            self._thread_local.tu_facts_batch_callgraph_invalidated = False

    def mark_tu_pending(self, tu_id: int, *, commit: bool = True):
        self._conn.execute(
            "UPDATE translation_units SET status = 'pending', last_modified = ? WHERE id = ?",
            (time.time(), tu_id),
        )
        self.mark_derived_indexes_dirty(
            reason="translation_unit_pending",
            commit=False,
        )
        if commit:
            self._conn.commit()

    def get_pending_tus(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, file_path, last_modified FROM translation_units WHERE status = 'pending'"
        ).fetchall()
        return [dict(r) for r in rows]

    # Inspection IR

    def upsert_ir_statement(
        self,
        file_path: str,
        line: int,
        function: str,
        kind: str = "",
        normalized_code: str = "",
        ast_kind: str = "",
        defs: str = "[]",
        uses: str = "[]",
    ) -> int:
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

    def insert_ir_resource_event(
        self,
        candidate_id: str,
        object_id: str,
        event_kind: str,
        api: str,
        file_path: str,
        line: int,
        function: str,
        owner_before: str = "",
        owner_after: str = "",
        condition: str = "",
        confidence: float = 0.5,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO ir_resource_events "
            "(candidate_id, object_id, event_kind, api, file_path, line, function, "
            "owner_before, owner_after, condition, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                candidate_id,
                object_id,
                event_kind,
                api,
                file_path,
                line,
                function,
                owner_before,
                owner_after,
                condition,
                confidence,
            ),
        )
        return int(cur.lastrowid or 0)

    def insert_ir_lock_event(
        self,
        candidate_id: str,
        lock_id: str,
        event_kind: str,
        file_path: str,
        line: int,
        function: str,
        path_id: str = "",
        held_before: str = "",
        held_after: str = "",
        confidence: float = 0.5,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO ir_lock_events "
            "(candidate_id, lock_id, event_kind, file_path, line, function, path_id, "
            "held_before, held_after, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                candidate_id,
                lock_id,
                event_kind,
                file_path,
                line,
                function,
                path_id,
                held_before,
                held_after,
                confidence,
            ),
        )
        return int(cur.lastrowid or 0)

    def insert_ir_shared_access(
        self,
        candidate_id: str,
        object_id: str,
        field: str,
        access_kind: str,
        file_path: str,
        line: int,
        function: str,
        guard_lock: str = "",
        thread_context: str = "",
        confidence: float = 0.5,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO ir_shared_accesses "
            "(candidate_id, object_id, field, access_kind, file_path, line, function, "
            "guard_lock, thread_context, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                candidate_id,
                object_id,
                field,
                access_kind,
                file_path,
                line,
                function,
                guard_lock,
                thread_context,
                confidence,
            ),
        )
        return int(cur.lastrowid or 0)

    def upsert_ir_path_slice(
        self,
        candidate_id: str,
        function: str,
        source_stmt: int = 0,
        sink_stmt: int = 0,
        path_summary: str = "{}",
        guards: str = "[]",
        contradictions: str = "[]",
        score_components: str = "{}",
    ) -> int:
        self._conn.execute(
            "INSERT OR REPLACE INTO ir_path_slices "
            "(candidate_id, function, source_stmt, sink_stmt, path_summary, guards, "
            "contradictions, score_components) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                candidate_id,
                function,
                source_stmt,
                sink_stmt,
                path_summary,
                guards,
                contradictions,
                score_components,
            ),
        )
        row = self._conn.execute(
            "SELECT id FROM ir_path_slices WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        return int(row["id"]) if row else 0

    def upsert_function_contract(
        self,
        function: str,
        allocates: str = "[]",
        releases: str = "[]",
        transfers: str = "[]",
        borrows: str = "[]",
        locks: str = "[]",
        thread_effects: str = "[]",
        return_semantics: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO function_contracts "
            "(function, allocates, releases, transfers, borrows, locks, "
            "thread_effects, return_semantics, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                function,
                allocates,
                releases,
                transfers,
                borrows,
                locks,
                thread_effects,
                return_semantics,
                time.time(),
            ),
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

    def _set_metadata_uncommitted(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value),
        )

    def set_metadata(self, key: str, value: str, *, commit: bool = True) -> None:
        """Persist a metadata key/value pair."""
        self._set_metadata_uncommitted(key, value)
        if commit:
            self._conn.commit()

    def delete_metadata(self, key: str, *, commit: bool = True) -> None:
        """Delete a metadata key when it exists."""
        self._conn.execute("DELETE FROM metadata WHERE key = ?", (key,))
        if commit:
            self._conn.commit()

    # -- Derived index lifecycle --

    @classmethod
    def _canonical_derived_index_name(cls, index_name: str) -> str:
        clean_name = str(index_name or "").strip()
        canonical = cls._DERIVED_INDEX_ALIASES.get(clean_name)
        if canonical is None:
            supported = ", ".join(cls.DERIVED_INDEX_NAMES)
            raise ValueError(
                f"unsupported derived index {clean_name!r}; expected one of: {supported}"
            )
        return canonical

    @classmethod
    def _derived_index_metadata_key(cls, index_name: str) -> str:
        canonical = cls._canonical_derived_index_name(index_name)
        return f"{cls.DERIVED_INDEX_METADATA_PREFIX}{canonical}"

    @staticmethod
    def _dirty_derived_index_state(reason: str) -> Dict[str, Any]:
        return {
            "applied_version": "",
            "target_version": "",
            "status": "dirty",
            "dirty_reason": str(reason or "invalid_state"),
            "last_error": "",
            "last_stats": {},
            "updated_at": 0.0,
        }

    @classmethod
    def _normalize_derived_index_state(cls, raw: str) -> Dict[str, Any]:
        if not raw:
            return cls._dirty_derived_index_state("missing_state")
        try:
            value = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return cls._dirty_derived_index_state("invalid_state")
        required = {
            "applied_version",
            "target_version",
            "status",
            "dirty_reason",
            "last_error",
            "last_stats",
            "updated_at",
        }
        if not isinstance(value, dict) or not required.issubset(value):
            return cls._dirty_derived_index_state("invalid_state")
        if not all(
            isinstance(value.get(field), str)
            for field in (
                "applied_version",
                "target_version",
                "status",
                "dirty_reason",
                "last_error",
            )
        ):
            return cls._dirty_derived_index_state("invalid_state")
        if value.get("status") not in cls._DERIVED_INDEX_STATUSES:
            return cls._dirty_derived_index_state("invalid_state")
        if not isinstance(value.get("last_stats"), dict):
            return cls._dirty_derived_index_state("invalid_state")
        updated_at = value.get("updated_at")
        if isinstance(updated_at, bool) or not isinstance(updated_at, (int, float)):
            return cls._dirty_derived_index_state("invalid_state")
        return {
            "applied_version": str(value["applied_version"]),
            "target_version": str(value["target_version"]),
            "status": str(value["status"]),
            "dirty_reason": str(value["dirty_reason"]),
            "last_error": str(value["last_error"]),
            "last_stats": dict(value["last_stats"]),
            "updated_at": float(updated_at),
        }

    def _write_derived_index_state_uncommitted(
        self,
        index_name: str,
        state: Dict[str, Any],
    ) -> None:
        canonical = self._canonical_derived_index_name(index_name)
        payload = {
            "applied_version": str(state.get("applied_version") or ""),
            "target_version": str(state.get("target_version") or ""),
            "status": str(state.get("status") or "dirty"),
            "dirty_reason": str(state.get("dirty_reason") or ""),
            "last_error": str(state.get("last_error") or ""),
            "last_stats": dict(state.get("last_stats") or {}),
            "updated_at": float(state.get("updated_at") or 0.0),
        }
        if payload["status"] not in self._DERIVED_INDEX_STATUSES:
            raise ValueError(f"invalid derived index status: {payload['status']!r}")
        self._set_metadata_uncommitted(
            f"{self.DERIVED_INDEX_METADATA_PREFIX}{canonical}",
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )

    def get_derived_index_state(self, index_name: str) -> Dict[str, Any]:
        """Return normalized lifecycle state; missing or corrupt metadata is dirty."""
        key = self._derived_index_metadata_key(index_name)
        return self._normalize_derived_index_state(self.get_metadata(key))

    def derived_index_needs_rebuild(self, index_name: str, target_version: str) -> bool:
        state = self.get_derived_index_state(index_name)
        return not (
            state["status"] == "current" and state["applied_version"] == str(target_version or "")
        )

    def mark_derived_indexes_dirty(
        self,
        index_names: Optional[Iterable[str]] = None,
        *,
        reason: str = "base_facts_changed",
        commit: bool = True,
    ) -> None:
        """Invalidate derived indexes while retaining their last complete rows."""
        if isinstance(index_names, str):
            requested_names: Iterable[str] = (index_names,)
        else:
            requested_names = index_names or self.DERIVED_INDEX_NAMES
        canonical_names = tuple(
            dict.fromkeys(self._canonical_derived_index_name(name) for name in requested_names)
        )
        with self._derived_index_lock:
            if self.DERIVED_INDEX_TYPE_REFS in canonical_names and self.get_metadata("clang_type_refs_generation"):
                import uuid
                self._set_metadata_uncommitted("clang_type_refs_generation", uuid.uuid4().hex)
            for canonical in canonical_names:
                previous = self.get_derived_index_state(canonical)
                self._write_derived_index_state_uncommitted(
                    canonical,
                    {
                        "applied_version": previous["applied_version"],
                        "target_version": previous["target_version"],
                        "status": "dirty",
                        "dirty_reason": str(reason or "base_facts_changed"),
                        "last_error": "",
                        "last_stats": previous["last_stats"],
                        "updated_at": time.time(),
                    },
                )
            if commit:
                self._conn.commit()

    def begin_derived_index_rebuild(
        self,
        index_name: str,
        target_version: str,
    ) -> Dict[str, Any]:
        """Durably mark a rebuild in progress before any staged work begins."""
        canonical = self._canonical_derived_index_name(index_name)
        with self._derived_index_lock:
            previous = self.get_derived_index_state(canonical)
            state = {
                "applied_version": previous["applied_version"],
                "target_version": str(target_version or ""),
                "status": "in_progress",
                "dirty_reason": previous["dirty_reason"],
                "last_error": "",
                "last_stats": {},
                "updated_at": time.time(),
            }
            self._write_derived_index_state_uncommitted(canonical, state)
            self._conn.commit()
            return dict(state)

    def prepare_derived_index_staging(self, index_name: str) -> None:
        """Create and clear connection-local TEMP tables for one derived rebuild."""
        canonical = self._canonical_derived_index_name(index_name)
        conn = self._conn
        with self._derived_index_lock:
            if canonical == self.DERIVED_INDEX_SYMBOL_CONTEXT:
                conn.execute(
                    f"CREATE TEMP TABLE IF NOT EXISTS {self._DERIVED_SYMBOL_REF_STAGE} ("
                    "function_name TEXT NOT NULL, function_file TEXT NOT NULL, "
                    "symbol_name TEXT NOT NULL, symbol_kind TEXT NOT NULL, "
                    "symbol_file TEXT DEFAULT '', reference_line INTEGER DEFAULT 0, "
                    "access_kind TEXT DEFAULT 'unknown', "
                    "UNIQUE(function_name, function_file, symbol_name, symbol_kind, "
                    "symbol_file, reference_line, access_kind))"
                )
                conn.execute(
                    f"CREATE TEMP TABLE IF NOT EXISTS {self._DERIVED_MACRO_REF_STAGE} ("
                    "function_id INTEGER NOT NULL, macro_id INTEGER NOT NULL, "
                    "reference_line INTEGER NOT NULL, "
                    "UNIQUE(function_id, macro_id, reference_line))"
                )
                conn.execute(f"DELETE FROM {self._DERIVED_SYMBOL_REF_STAGE}")
                conn.execute(f"DELETE FROM {self._DERIVED_MACRO_REF_STAGE}")
            else:
                conn.execute(
                    f"CREATE TEMP TABLE IF NOT EXISTS {self._DERIVED_TYPE_REF_STAGE} ("
                    "function_id INTEGER NOT NULL, type_id INTEGER, "
                    "type_index_name TEXT NOT NULL DEFAULT '', "
                    "referenced_name TEXT NOT NULL, reference_file TEXT NOT NULL, "
                    "reference_line INTEGER NOT NULL, reference_kind TEXT NOT NULL, "
                    "resolution_reason TEXT DEFAULT '', "
                    "UNIQUE(function_id, referenced_name, type_index_name, "
                    "reference_line, reference_kind))"
                )
                conn.execute(f"DELETE FROM {self._DERIVED_TYPE_REF_STAGE}")

    def discard_derived_index_staging(self, index_name: str) -> None:
        """Drop connection-local staging tables without changing lifecycle state."""
        canonical = self._canonical_derived_index_name(index_name)
        conn = self._conn
        with self._derived_index_lock:
            if canonical == self.DERIVED_INDEX_SYMBOL_CONTEXT:
                conn.execute(f"DROP TABLE IF EXISTS temp.{self._DERIVED_SYMBOL_REF_STAGE}")
                conn.execute(f"DROP TABLE IF EXISTS temp.{self._DERIVED_MACRO_REF_STAGE}")
            else:
                conn.execute(f"DROP TABLE IF EXISTS temp.{self._DERIVED_TYPE_REF_STAGE}")

    def stage_function_symbol_refs_batch(self, rows: List[tuple]) -> None:
        if rows:
            self._conn.executemany(
                f"INSERT OR IGNORE INTO {self._DERIVED_SYMBOL_REF_STAGE} "
                "(function_name, function_file, symbol_name, symbol_kind, symbol_file, "
                "reference_line, access_kind) VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def stage_function_macro_refs_batch(self, rows: List[tuple]) -> None:
        if rows:
            self._conn.executemany(
                f"INSERT OR IGNORE INTO {self._DERIVED_MACRO_REF_STAGE} "
                "(function_id, macro_id, reference_line) VALUES (?, ?, ?)",
                rows,
            )

    def stage_function_type_refs_batch(self, rows: List[tuple]) -> None:
        if rows:
            self._conn.executemany(
                f"INSERT OR REPLACE INTO {self._DERIVED_TYPE_REF_STAGE} "
                "(function_id, type_id, type_index_name, referenced_name, reference_file, "
                "reference_line, reference_kind, resolution_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def _temporary_table_exists(self, table_name: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM sqlite_temp_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None

    def finalize_derived_index_rebuild(
        self,
        index_name: str,
        target_version: str,
        last_stats: Optional[Dict[str, Any]] = None,
        *,
        merge_files: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Atomically publish staged rows and their matching current state.

        With merge_files the target index keeps rows for every other function
        file and only the affected files' rows are replaced from staging; the
        staged rows must therefore cover exactly those files.
        """
        canonical = self._canonical_derived_index_name(index_name)
        target = str(target_version or "")
        conn = self._conn
        with self._derived_index_lock:
            previous = self.get_derived_index_state(canonical)
            if previous["status"] != "in_progress" or previous["target_version"] != target:
                raise RuntimeError(
                    "derived index finalize requires matching in_progress state: "
                    f"index={canonical} target={target!r} state={previous!r}"
                )
            required_staging = (
                (self._DERIVED_SYMBOL_REF_STAGE, self._DERIVED_MACRO_REF_STAGE)
                if canonical == self.DERIVED_INDEX_SYMBOL_CONTEXT
                else (self._DERIVED_TYPE_REF_STAGE,)
            )
            missing = [name for name in required_staging if not self._temporary_table_exists(name)]
            if missing:
                raise RuntimeError(
                    f"derived index staging was not prepared for {canonical}: {', '.join(missing)}"
                )

            state = {
                "applied_version": target,
                "target_version": target,
                "status": "current",
                "dirty_reason": "",
                "last_error": "",
                "last_stats": dict(last_stats or {}),
                "updated_at": time.time(),
            }
            savepoint = f"finalize_{canonical}"
            savepoint_active = False
            try:
                conn.execute(f"SAVEPOINT {savepoint}")
                savepoint_active = True
                merge_scope: bool = merge_files is not None
                if merge_scope:
                    conn.execute(
                        "CREATE TEMP TABLE IF NOT EXISTS derived_merge_files ("
                        "path TEXT PRIMARY KEY)"
                    )
                    conn.execute("DELETE FROM derived_merge_files")
                    merge_rows = [
                        (variant,)
                        for file_path in merge_files or ()
                        for variant in self._path_variants(str(file_path))
                        if variant
                    ]
                    if merge_rows:
                        conn.executemany(
                            "INSERT OR IGNORE INTO derived_merge_files(path) VALUES (?)",
                            merge_rows,
                        )
                if canonical == self.DERIVED_INDEX_SYMBOL_CONTEXT:
                    if merge_scope:
                        conn.execute(
                            "DELETE FROM function_symbol_refs WHERE function_file IN "
                            "(SELECT path FROM derived_merge_files)"
                        )
                        conn.execute(
                            "DELETE FROM function_macro_refs WHERE function_id IN "
                            "(SELECT id FROM functions WHERE file_path IN "
                            "(SELECT path FROM derived_merge_files))"
                        )
                    else:
                        conn.execute("DELETE FROM function_symbol_refs")
                        conn.execute("DELETE FROM function_macro_refs")
                    conn.execute(
                        "INSERT INTO function_symbol_refs "
                        "(function_name, function_file, symbol_name, symbol_kind, symbol_file, "
                        "reference_line, access_kind) "
                        f"SELECT function_name, function_file, symbol_name, symbol_kind, "
                        f"symbol_file, reference_line, CASE "
                        f"WHEN MAX(CASE WHEN access_kind = 'read_write' THEN 1 ELSE 0 END) = 1 "
                        f"OR (MAX(CASE WHEN access_kind = 'read' THEN 1 ELSE 0 END) = 1 "
                        f"AND MAX(CASE WHEN access_kind = 'write' THEN 1 ELSE 0 END) = 1) "
                        f"THEN 'read_write' "
                        f"WHEN MAX(CASE WHEN access_kind = 'write' THEN 1 ELSE 0 END) = 1 "
                        f"THEN 'write' "
                        f"WHEN MAX(CASE WHEN access_kind = 'read' THEN 1 ELSE 0 END) = 1 "
                        f"THEN 'read' ELSE 'unknown' END "
                        f"FROM {self._DERIVED_SYMBOL_REF_STAGE} "
                        f"GROUP BY function_name, function_file, symbol_name, symbol_kind, "
                        f"symbol_file, reference_line"
                    )
                    conn.execute(
                        "INSERT INTO function_macro_refs "
                        "(function_id, macro_id, reference_line) "
                        f"SELECT function_id, macro_id, reference_line "
                        f"FROM {self._DERIVED_MACRO_REF_STAGE}"
                    )
                else:
                    if merge_scope:
                        conn.execute(
                            "DELETE FROM function_type_refs WHERE function_id IN "
                            "(SELECT id FROM functions WHERE file_path IN "
                            "(SELECT path FROM derived_merge_files))"
                        )
                    else:
                        conn.execute("DELETE FROM function_type_refs")
                    conn.execute(
                        "INSERT INTO function_type_refs "
                        "(function_id, type_id, type_index_name, referenced_name, "
                        "reference_file, reference_line, reference_kind, resolution_reason) "
                        f"SELECT function_id, type_id, type_index_name, referenced_name, "
                        f"reference_file, reference_line, reference_kind, resolution_reason "
                        f"FROM {self._DERIVED_TYPE_REF_STAGE}"
                    )
                self._write_derived_index_state_uncommitted(canonical, state)
                conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                savepoint_active = False
                conn.commit()
            except BaseException:
                if savepoint_active:
                    conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                conn.rollback()
                raise
            try:
                for table_name in required_staging:
                    conn.execute(f"DELETE FROM {table_name}")
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                logger.debug(
                    "Unable to clear published derived staging index=%s: %s",
                    canonical,
                    exc,
                )
            return dict(state)

    def fail_derived_index_rebuild(
        self,
        index_name: str,
        target_version: str,
        error: Any,
        last_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Persist a failed rebuild while retaining the last applied version."""
        canonical = self._canonical_derived_index_name(index_name)
        with self._derived_index_lock:
            previous = self.get_derived_index_state(canonical)
            state = {
                "applied_version": previous["applied_version"],
                "target_version": str(target_version or ""),
                "status": "failed",
                "dirty_reason": previous["dirty_reason"] or "rebuild_failed",
                "last_error": str(error or "derived index rebuild failed"),
                "last_stats": dict(last_stats or previous["last_stats"] or {}),
                "updated_at": time.time(),
            }
            self._write_derived_index_state_uncommitted(canonical, state)
            self._conn.commit()
            return dict(state)

    def get_svf_db_generation(self) -> int:
        """Return the generation of SVF-derived rows in this database."""
        raw = self.get_metadata("svf_db_generation")
        try:
            return max(0, int(raw or 0))
        except (TypeError, ValueError):
            logger.warning("Invalid svf_db_generation metadata %r; treating it as 0", raw)
            return 0

    @contextmanager
    def svf_materialization_transaction(self) -> Iterator[None]:
        """Serialize and atomically commit one SVF group replacement."""
        with self._svf_materialization_lock:
            conn = self._conn
            savepoint = f"svf_materialization_{threading.get_ident()}"
            conn.execute(f"SAVEPOINT {savepoint}")
            try:
                yield
            except Exception:
                conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            else:
                conn.execute(f"RELEASE SAVEPOINT {savepoint}")

    def get_svf_hash(self) -> str:
        """获取上次 SVF 分析时的源码聚合哈希。"""
        return self.get_metadata("svf_source_hash")

    def set_svf_hash(self, hash_value: str):
        """记录 SVF 源码聚合哈希。"""
        conn = self._conn
        self._set_metadata_uncommitted("svf_source_hash", hash_value)
        if hash_value:
            conn.execute(
                "DELETE FROM metadata WHERE key IN (?, ?)",
                (self.TAINT_REINDEX_REQUIRED_KEY, self.TAINT_REINDEX_REASON_KEY),
            )
        conn.commit()

    def purge_svf_data(
        self,
        group: str = "default",
        *,
        commit: bool = True,
        delete_marker: bool = True,
    ):
        """清除 SVF 产生的间接调用和污点数据（按分组）。"""
        self._invalidate_callgraph_query_cache()
        self._conn.execute("DELETE FROM indirect_calls WHERE svf_group = ?", (group,))
        self._conn.execute("DELETE FROM taint_signatures WHERE svf_group = ?", (group,))
        if delete_marker:
            for tool in ("ander", "saber"):
                self._conn.execute(
                    "DELETE FROM metadata WHERE key = ?",
                    (f"svf_db_import:{tool}:{group}",),
                )
        if commit:
            self._conn.commit()

    def purge_svf_data_except(self, groups: set[str]):
        """Remove stale SVF rows whose group is not part of the current refresh."""
        self._invalidate_callgraph_query_cache()
        clean_groups = sorted(str(group) for group in groups if str(group))
        if not clean_groups:
            self._conn.execute("DELETE FROM indirect_calls")
            self._conn.execute("DELETE FROM taint_signatures")
            self._conn.execute("DELETE FROM metadata WHERE key LIKE 'svf_db_import:%'")
            self._conn.commit()
            return
        placeholders = ",".join("?" for _ in clean_groups)
        self._conn.execute(
            f"DELETE FROM indirect_calls WHERE svf_group NOT IN ({placeholders})",
            clean_groups,
        )
        self._conn.execute(
            f"DELETE FROM taint_signatures WHERE svf_group NOT IN ({placeholders})",
            clean_groups,
        )
        marker_rows = self._conn.execute(
            "SELECT key FROM metadata WHERE key LIKE 'svf_db_import:%'"
        ).fetchall()
        for row in marker_rows:
            key = str(row["key"] or "")
            remainder = key[len("svf_db_import:") :]
            _separator, _tool, marker_group = remainder.partition(":")
            if marker_group and marker_group not in clean_groups:
                self._conn.execute("DELETE FROM metadata WHERE key = ?", (key,))
        self._conn.commit()

    # ── Functions ──

    def insert_function(
        self,
        name: str,
        file_path: str,
        start_line: int,
        end_line: int,
        signature: str = "",
        is_static: bool = False,
        is_inline: bool = False,
        is_declaration: bool = False,
        tu_id: Optional[int] = None,
    ):
        self._conn.execute(
            "INSERT OR REPLACE INTO functions "
            "(name, file_path, start_line, end_line, signature, is_static, is_inline, is_declaration, tu_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                file_path,
                start_line,
                end_line,
                signature,
                int(is_static),
                int(is_inline),
                int(is_declaration),
                tu_id,
            ),
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

    def get_functions_by_name(self, name: str) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM functions WHERE name = ? AND is_declaration = 0 "
            "ORDER BY file_path, start_line",
            (name,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_all_functions(self) -> Dict[str, Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, file_path, start_line, end_line, signature, is_static "
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
                "is_static": bool(r["is_static"]),
            }
        return index

    def get_function_records(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, name, file_path, start_line, end_line, signature, is_static, "
            "is_declaration, tu_id "
            "FROM functions ORDER BY file_path, start_line, name"
        ).fetchall()
        return [dict(row) for row in rows]

    # -- Global variables and function symbol references --

    def insert_global_variable(
        self,
        name: str,
        type_str: str,
        file_path: str,
        line: int,
        *,
        is_extern: bool = False,
        storage_class: str = "unknown",
        qualifiers: str = "",
        initializer: str = "",
        definition_kind: str = "unknown",
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO global_variables "
            "(name, type_str, file_path, line, is_extern, storage_class, qualifiers, "
            "initializer, definition_kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                type_str,
                file_path,
                int(line),
                int(bool(is_extern)),
                storage_class,
                qualifiers,
                initializer,
                definition_kind,
            ),
        )

    def insert_global_variables_batch(self, rows: List[tuple]) -> None:
        if rows:
            self._conn.executemany(
                "INSERT OR REPLACE INTO global_variables "
                "(name, type_str, file_path, line, is_extern, storage_class, qualifiers, "
                "initializer, definition_kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def get_global_variables(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, type_str, file_path, line, is_extern, storage_class, "
            "qualifiers, initializer, definition_kind FROM global_variables "
            "ORDER BY name, file_path, line"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_all_macro_definitions(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, macro_index_name, name, file_path, line, start_line, end_line, "
            "definition, is_function_like FROM macro_definitions "
            "ORDER BY macro_index_name"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_macro_definition_records(self) -> List[Dict[str, Any]]:
        """Return macro identities for derived refs without loading macro bodies."""
        rows = self._conn.execute(
            "SELECT id, macro_index_name, name, file_path, line, start_line, end_line, "
            "is_function_like FROM macro_definitions "
            "ORDER BY name, file_path, line"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_macro_definitions_batch(self, names: List[str]) -> List[Dict[str, Any]]:
        """Return all macro definitions matching the supplied names."""
        clean_names = sorted({str(name or "").strip() for name in names if str(name or "").strip()})
        result: List[Dict[str, Any]] = []
        for offset in range(0, len(clean_names), 500):
            batch = clean_names[offset : offset + 500]
            placeholders = ",".join("?" for _ in batch)
            macro_rows = self._conn.execute(
                "SELECT id, macro_index_name, name, file_path, line, start_line, end_line, "
                "definition, is_function_like "
                "FROM macro_definitions "
                f"WHERE name IN ({placeholders}) ORDER BY macro_index_name",
                batch,
            ).fetchall()
            result.extend(dict(row) for row in macro_rows)
        return result

    def insert_function_symbol_refs_batch(self, rows: List[tuple]) -> None:
        if not rows:
            return
        self._conn.executemany(
            "INSERT OR REPLACE INTO function_symbol_refs "
            "(function_name, function_file, symbol_name, symbol_kind, symbol_file, "
            "reference_line, access_kind) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    def replace_function_symbol_context(
        self,
        symbol_rows: List[tuple],
        macro_rows: List[tuple],
    ) -> None:
        """Atomically replace the permanent symbol and macro reference tables."""
        conn = self._conn
        conn.execute("SAVEPOINT replace_function_symbol_context")
        try:
            conn.execute("DELETE FROM function_symbol_refs")
            conn.execute("DELETE FROM function_macro_refs")
            if symbol_rows:
                conn.executemany(
                    "INSERT OR REPLACE INTO function_symbol_refs "
                    "(function_name, function_file, symbol_name, symbol_kind, symbol_file, "
                    "reference_line, access_kind) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    symbol_rows,
                )
            if macro_rows:
                conn.executemany(
                    "INSERT OR REPLACE INTO function_macro_refs "
                    "(function_id, macro_id, reference_line) VALUES (?, ?, ?)",
                    macro_rows,
                )
            conn.execute("RELEASE SAVEPOINT replace_function_symbol_context")
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT replace_function_symbol_context")
            conn.execute("RELEASE SAVEPOINT replace_function_symbol_context")
            raise

    def clear_function_symbol_refs(self) -> None:
        self._conn.execute("DELETE FROM function_symbol_refs")

    def replace_function_macro_refs(self, rows: List[tuple]) -> None:
        self._conn.execute("DELETE FROM function_macro_refs")
        self.insert_function_macro_refs_batch(rows)

    def insert_function_macro_refs_batch(self, rows: List[tuple]) -> None:
        if rows:
            self._conn.executemany(
                "INSERT OR REPLACE INTO function_macro_refs "
                "(function_id, macro_id, reference_line) VALUES (?, ?, ?)",
                rows,
            )

    def clear_function_macro_refs(self) -> None:
        self._conn.execute("DELETE FROM function_macro_refs")

    def get_function_symbol_context(
        self,
        function_name: str,
        function_file: str = "",
    ) -> Dict[str, List[Dict[str, Any]]]:
        rows = self._conn.execute(
            "SELECT function_file, symbol_name, symbol_kind, symbol_file, "
            "reference_line, access_kind FROM function_symbol_refs "
            "WHERE function_name = ? ORDER BY symbol_kind, symbol_name, symbol_file, reference_line",
            (function_name,),
        ).fetchall()
        if function_file:
            rows = [
                row
                for row in rows
                if self._paths_match_hint(str(row["function_file"] or ""), function_file)
            ]

        globals_by_key = {
            (str(row["name"]), str(row["file_path"])): dict(row)
            for row in self._conn.execute(
                "SELECT name, type_str, file_path, line, is_extern, storage_class, "
                "qualifiers, initializer, definition_kind FROM global_variables"
            ).fetchall()
        }
        global_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in rows:
            name = str(row["symbol_name"] or "")
            symbol_file = str(row["symbol_file"] or "")
            reference_line = int(row["reference_line"] or 0)
            if row["symbol_kind"] == "global":
                key = (name, symbol_file)
                entry = global_groups.get(key)
                if entry is None:
                    metadata = globals_by_key.get(key, {})
                    entry = {
                        "name": name,
                        "type": str(metadata.get("type_str") or ""),
                        "file_path": symbol_file,
                        "line": int(metadata.get("line") or 0),
                        "is_extern": bool(metadata.get("is_extern")),
                        "storage_class": str(metadata.get("storage_class") or "unknown"),
                        "qualifiers": str(metadata.get("qualifiers") or ""),
                        "initializer": str(metadata.get("initializer") or ""),
                        "definition_kind": str(metadata.get("definition_kind") or "unknown"),
                        "access": "unknown",
                        "reference_lines": [],
                    }
                    global_groups[key] = entry
                entry["access"] = self._merge_access_kind(
                    str(entry.get("access") or "unknown"),
                    str(row["access_kind"] or "unknown"),
                )
                if reference_line > 0 and reference_line not in entry["reference_lines"]:
                    entry["reference_lines"].append(reference_line)
        globals_result = list(global_groups.values())
        for entry in globals_result:
            entry["reference_lines"] = sorted(entry["reference_lines"])
        globals_result.sort(key=lambda item: (item["name"], item["file_path"], item["line"]))

        macro_rows = self._conn.execute(
            "SELECT f.file_path AS function_file, md.macro_index_name, "
            "md.is_function_like, fmr.reference_line "
            "FROM function_macro_refs fmr "
            "JOIN functions f ON f.id = fmr.function_id "
            "JOIN macro_definitions md ON md.id = fmr.macro_id "
            "WHERE f.name = ? ORDER BY md.macro_index_name, fmr.reference_line",
            (function_name,),
        ).fetchall()
        if function_file:
            macro_rows = [
                row
                for row in macro_rows
                if self._paths_match_hint(str(row["function_file"] or ""), function_file)
            ]
        macro_groups: Dict[str, Dict[str, Any]] = {}
        for row in macro_rows:
            macro_index_name = str(row["macro_index_name"] or "")
            if not macro_index_name:
                continue
            entry = macro_groups.setdefault(
                macro_index_name,
                {
                    "macro_index_name": macro_index_name,
                    "is_function_like": bool(row["is_function_like"]),
                    "reference_lines": [],
                },
            )
            reference_line = int(row["reference_line"] or 0)
            if reference_line > 0 and reference_line not in entry["reference_lines"]:
                entry["reference_lines"].append(reference_line)
        macros_result = [macro_groups[key] for key in sorted(macro_groups)]
        for entry in macros_result:
            entry["reference_lines"] = sorted(entry["reference_lines"])
        return {
            "referenced_globals": globals_result,
            "referenced_macros": macros_result,
        }

    @staticmethod
    def _merge_access_kind(left: str, right: str) -> str:
        values = {left or "unknown", right or "unknown"}
        if "read_write" in values or {"read", "write"}.issubset(values):
            return "read_write"
        if "write" in values:
            return "write"
        if "read" in values:
            return "read"
        return "unknown"

    # -- Macro definitions --

    def insert_macro_definitions_batch(self, rows: List[tuple]):
        normalized_rows: List[tuple] = []
        for row in rows:
            if len(row) == 7:
                (
                    name,
                    file_path,
                    start_line,
                    end_line,
                    macro_index_name,
                    definition,
                    is_function_like,
                ) = row
            elif len(row) == 5:
                name, file_path, start_line, definition, is_function_like = row
                definition_lines = str(definition or "").splitlines()
                end_line = int(start_line) + max(1, len(definition_lines)) - 1
                macro_index_name = f"{name}@{file_path}:{int(start_line)}-{int(end_line)}"
            else:
                raise ValueError("macro definition row must contain 5 or 7 fields")
            normalized_rows.append(
                (
                    str(macro_index_name),
                    str(name),
                    str(file_path),
                    int(start_line),
                    int(start_line),
                    int(end_line),
                    str(definition or ""),
                    int(bool(is_function_like)),
                )
            )
        self._conn.executemany(
            "INSERT OR REPLACE INTO macro_definitions "
            "(macro_index_name, name, file_path, line, start_line, end_line, definition, "
            "is_function_like) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            normalized_rows,
        )

    def get_macro_definitions(self, name: str, limit: int = 20) -> List[Dict[str, Any]]:
        clean_name = str(name or "").strip()
        if not clean_name:
            return []
        rows = self._conn.execute(
            "SELECT id, macro_index_name, name, file_path, line, start_line, end_line, "
            "definition, is_function_like "
            "FROM macro_definitions WHERE name = ? "
            "ORDER BY is_function_like DESC, macro_index_name ASC LIMIT ?",
            (clean_name, int(limit or 20)),
        ).fetchall()
        return [dict(row) for row in rows]

    def clear_macro_definitions(self) -> None:
        self._conn.execute("DELETE FROM function_macro_refs")
        self._conn.execute("DELETE FROM macro_definitions")
        self.mark_derived_indexes_dirty(
            (self.DERIVED_INDEX_SYMBOL_CONTEXT,),
            reason="macro_definitions_cleared",
            commit=False,
        )
        self._conn.commit()

    @staticmethod
    def _function_signature_key(name: str, signature: str) -> str:
        if "(" not in signature or ")" not in signature:
            return name
        params = signature[signature.find("(") + 1 : signature.rfind(")")].strip()
        params = " ".join(params.split())
        return f"{name}({params})"

    # ── Type Definitions ──

    def insert_type(
        self,
        name: str,
        kind: str,
        file_path: str,
        start_line: int,
        end_line: int,
        full_definition: str = "",
        tu_id: Optional[int] = None,
    ) -> int:
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

    def insert_types_with_members_batch(self, rows: List[tuple], tu_id: int) -> None:
        """Insert all type definitions/members for one TU with three SQL batches."""
        if not rows:
            return
        self._conn.executemany(
            "INSERT OR REPLACE INTO type_definitions "
            "(name, kind, file_path, start_line, end_line, full_definition, tu_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(*row[:6], int(tu_id)) for row in rows],
        )
        identities = self._conn.execute(
            "SELECT id, name, kind, file_path FROM type_definitions WHERE tu_id = ?",
            (int(tu_id),),
        ).fetchall()
        ids = {
            (str(row["name"]), str(row["kind"]), str(row["file_path"])): int(row["id"])
            for row in identities
        }
        member_rows: List[tuple] = []
        for row in rows:
            type_id = ids.get((str(row[0]), str(row[1]), str(row[2])))
            if type_id is None:
                continue
            member_rows.extend(
                (type_id, str(name), str(member_type), int(offset_idx))
                for name, member_type, offset_idx in row[6]
            )
        if member_rows:
            self._conn.executemany(
                "INSERT OR REPLACE INTO type_members "
                "(type_id, member_name, member_type, offset_idx) VALUES (?, ?, ?, ?)",
                member_rows,
            )

    def insert_type_member(
        self, type_id: int, member_name: str, member_type: str = "", offset_idx: int = 0
    ):
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
            "WHERE type_id = ? ORDER BY offset_idx",
            (row["id"],),
        ).fetchall()
        result["members"] = [dict(m) for m in members]
        return result

    def find_type_infos(
        self,
        name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM type_definitions WHERE name = ? "
            "ORDER BY file_path, start_line, kind, name",
            (name,),
        ).fetchall()
        if file_path:
            rows = [
                row
                for row in rows
                if self._paths_match_hint(str(row["file_path"] or ""), file_path)
            ]

        result: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item.pop("id", None)
            item.pop("tu_id", None)
            result.append(item)
        return result

    @staticmethod
    def type_index_name(type_info: Dict[str, Any]) -> str:
        """Build the public canonical identity for one indexed type definition."""
        name = str(type_info.get("name") or "").strip()
        kind = str(type_info.get("kind") or "unknown").strip() or "unknown"
        file_path = str(type_info.get("file_path") or "").replace("\\", "/").lstrip("./")
        start_line = int(type_info.get("start_line") or 0)
        end_line = int(type_info.get("end_line") or start_line)
        identity_name = name or f"anonymous-{kind}"
        return f"{identity_name}@{file_path}:{start_line}-{end_line}"

    def get_all_type_definitions(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, name, kind, file_path, start_line, end_line, full_definition, tu_id "
            "FROM type_definitions ORDER BY name, file_path, start_line, end_line, kind"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_type_definition_records(self) -> List[Dict[str, Any]]:
        """Return lightweight type identities for derived-reference rebuilding."""
        rows = self._conn.execute(
            "SELECT id, name, kind, file_path, start_line, end_line, tu_id, "
            "CASE WHEN COALESCE(full_definition, '') != '' THEN 1 ELSE 0 END AS has_definition "
            "FROM type_definitions ORDER BY name, file_path, start_line, end_line, kind"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_transitive_include_closure(self, source_file: str) -> List[str]:
        """Return normalized non-system files transitively visible from source_file."""
        return self.get_transitive_include_closures((source_file,)).get(str(source_file), [])

    def insert_include_edges_batch(self, rows: Iterable[tuple]) -> None:
        """Insert include edges in one SQLite batch, ignoring duplicate facts."""
        self._conn.executemany(
            "INSERT OR IGNORE INTO include_edges "
            "(source_file, included_file, line, is_system) VALUES (?, ?, ?, ?)",
            rows,
        )

    def get_transitive_include_closures(
        self,
        source_files: Iterable[str],
    ) -> Dict[str, List[str]]:
        """Return closures using one graph read and memoized SCC condensation."""
        requested = [str(source_file) for source_file in source_files]
        rows = self._conn.execute(
            "SELECT source_file, included_file FROM include_edges "
            "WHERE is_system = 0 ORDER BY source_file, included_file"
        ).fetchall()
        graph: Dict[str, set[str]] = {}
        for row in rows:
            source = self._normalize_include_graph_path(str(row["source_file"] or ""))
            included = self._normalize_include_graph_path(str(row["included_file"] or ""))
            if source and included:
                graph.setdefault(source, set()).add(included)
                graph.setdefault(included, set())

        # Iterative Kosaraju SCC turns an include graph with cycles into a DAG
        # without consuming Python recursion depth on long include chains.
        ordered_neighbors = {node: tuple(sorted(neighbors)) for node, neighbors in graph.items()}
        reverse_graph: Dict[str, set[str]] = {node: set() for node in graph}
        for source, included_files in graph.items():
            for included in included_files:
                reverse_graph[included].add(source)

        visited: set[str] = set()
        finish_order: List[str] = []
        for start in sorted(graph):
            if start in visited:
                continue
            visited.add(start)
            pending: List[Tuple[str, Iterator[str]]] = [(start, iter(ordered_neighbors[start]))]
            while pending:
                node, neighbors = pending[-1]
                try:
                    neighbor = next(neighbors)
                except StopIteration:
                    finish_order.append(node)
                    pending.pop()
                    continue
                if neighbor not in visited:
                    visited.add(neighbor)
                    pending.append((neighbor, iter(ordered_neighbors[neighbor])))

        components: List[Tuple[str, ...]] = []
        assigned: set[str] = set()
        for start in reversed(finish_order):
            if start in assigned:
                continue
            component: List[str] = []
            pending_nodes = [start]
            assigned.add(start)
            while pending_nodes:
                node = pending_nodes.pop()
                component.append(node)
                for neighbor in reverse_graph[node]:
                    if neighbor not in assigned:
                        assigned.add(neighbor)
                        pending_nodes.append(neighbor)
            components.append(tuple(sorted(component)))

        component_by_node: Dict[str, int] = {}
        for component_id, completed_component in enumerate(components):
            for node in completed_component:
                component_by_node[node] = component_id
        component_edges: Dict[int, set[int]] = {idx: set() for idx in range(len(components))}
        for source, included_files in graph.items():
            source_component = component_by_node[source]
            for included in included_files:
                target_component = component_by_node[included]
                if source_component != target_component:
                    component_edges[source_component].add(target_component)

        closure_cache: Dict[int, frozenset[str]] = {}

        def component_closure(component_id: int) -> frozenset[str]:
            cached = closure_cache.get(component_id)
            if cached is not None:
                return cached
            active = {component_id}
            pending_components: List[Tuple[int, Iterator[int]]] = [
                (component_id, iter(component_edges[component_id]))
            ]
            while pending_components:
                current, children = pending_components[-1]
                try:
                    child = next(children)
                except StopIteration:
                    closure = set(components[current])
                    for child in component_edges[current]:
                        closure.update(closure_cache[child])
                    closure_cache[current] = frozenset(closure)
                    active.remove(current)
                    pending_components.pop()
                    continue
                if child in closure_cache:
                    continue
                if child in active:
                    raise RuntimeError("include component graph unexpectedly contains a cycle")
                active.add(child)
                pending_components.append((child, iter(component_edges[child])))
            return closure_cache[component_id]

        # Resolve exact normalized paths in O(1). For legacy absolute-vs-relative
        # rows, suffix aliases retain the prior matching semantics without scanning
        # every graph node for each requested source.
        exact_nodes = set(graph)
        suffix_index: Dict[str, set[str]] = {}
        for node in exact_nodes:
            parts = node.split("/")
            for offset in range(len(parts)):
                suffix_index.setdefault("/".join(parts[offset:]), set()).add(node)

        result: Dict[str, List[str]] = {}
        for source_file in requested:
            clean_source = self._normalize_include_graph_path(source_file)
            if clean_source in exact_nodes:
                roots = {clean_source}
            else:
                roots = set(suffix_index.get(clean_source, ()))
                if not roots and clean_source:
                    clean_parts = clean_source.split("/")
                    for offset in range(1, len(clean_parts)):
                        candidate = "/".join(clean_parts[offset:])
                        if candidate in exact_nodes:
                            roots.add(candidate)
            closure: set[str] = set()
            for root in roots:
                closure.update(component_closure(component_by_node[root]))
            if not roots and clean_source:
                closure.add(clean_source)
            result[source_file] = sorted(closure)
        return result

    def compute_derived_affected_files(
        self,
        changed_files: Iterable[str],
        candidate_files: Iterable[str],
        *,
        max_affected_ratio: float = 0.5,
    ) -> Optional[Set[str]]:
        """Return candidate files affected by base changes via reverse include closure.

        A candidate is affected when it changed itself or its transitive
        include closure touches any changed path.  Matching is deliberately
        conservative (basename-level prefilter plus canonical path variants)
        so the result is a superset of the truly affected files.  Returns
        None when a partial merge would not beat a full rebuild (affected set
        exceeds max_affected_ratio of the candidates).
        """
        changed_variants: Set[str] = set()
        changed_basenames: Set[str] = set()
        for raw in changed_files or ():
            if not str(raw or ""):
                continue
            for variant in self._path_variants(str(raw)):
                changed_variants.add(self._normalize_include_graph_path(variant))
                changed_basenames.add(Path(variant).name)
        if not changed_basenames:
            return set()
        candidates = [str(item or "") for item in candidate_files if str(item or "")]
        if not candidates:
            return set()
        closures = self.get_transitive_include_closures(candidates)
        affected: Set[str] = set()
        for file_path in candidates:
            normalized = self._normalize_include_graph_path(file_path)
            if (
                Path(file_path).name in changed_basenames
                or normalized in changed_variants
            ):
                affected.add(file_path)
                continue
            for member in closures.get(file_path) or ():
                if Path(str(member)).name in changed_basenames:
                    affected.add(file_path)
                    break
        if len(affected) > int(len(candidates) * max_affected_ratio):
            return None
        return affected

    @staticmethod
    def _normalize_include_graph_path(path: str) -> str:
        value = str(path or "").replace("\\", "/").strip()
        while value.startswith("./"):
            value = value[2:]
        return value.rstrip("/")

    def replace_function_type_refs(self, rows: List[tuple]) -> None:
        """Atomically replace all direct function-to-type reference facts."""
        conn = self._conn
        conn.execute("SAVEPOINT replace_function_type_refs")
        try:
            conn.execute("DELETE FROM function_type_refs")
            if rows:
                conn.executemany(
                    "INSERT OR REPLACE INTO function_type_refs "
                    "(function_id, type_id, type_index_name, referenced_name, "
                    "reference_file, reference_line, reference_kind, resolution_reason) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
            conn.execute("RELEASE SAVEPOINT replace_function_type_refs")
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT replace_function_type_refs")
            conn.execute("RELEASE SAVEPOINT replace_function_type_refs")
            raise

    def clear_function_type_refs(self) -> None:
        self._conn.execute("DELETE FROM function_type_refs")

    def get_function_type_context(
        self,
        function_name: str,
        function_file: str = "",
        function_start_line: int = 0,
    ) -> Dict[str, Any]:
        """Return aggregated direct type references for one function identity."""
        function_rows = self._conn.execute(
            "SELECT id, file_path, start_line FROM functions "
            "WHERE name = ? AND is_declaration = 0 ORDER BY file_path, start_line",
            (function_name,),
        ).fetchall()
        if function_file:
            function_rows = [
                row
                for row in function_rows
                if self._paths_match_hint(str(row["file_path"] or ""), function_file)
            ]
        if function_start_line:
            function_rows = [
                row
                for row in function_rows
                if int(row["start_line"] or 0) == int(function_start_line)
            ]
        if len(function_rows) != 1:
            return {"referenced_types": []}

        rows = self._conn.execute(
            "SELECT r.type_id, r.type_index_name, r.referenced_name, "
            "r.reference_file, r.reference_line, r.reference_kind, "
            "r.resolution_reason, t.name, t.kind, t.file_path, t.start_line, "
            "t.end_line, t.full_definition "
            "FROM function_type_refs r "
            "LEFT JOIN type_definitions t ON t.id = r.type_id "
            "WHERE r.function_id = ? "
            "ORDER BY r.type_index_name, r.referenced_name, r.reference_kind, "
            "r.reference_line",
            (int(function_rows[0]["id"]),),
        ).fetchall()

        resolved: Dict[str, Dict[str, Any]] = {}
        unresolved: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in rows:
            reference_line = int(row["reference_line"] or 0)
            reference_kind = str(row["reference_kind"] or "")
            if row["type_id"] is not None and row["name"] is not None:
                identity = str(row["type_index_name"] or "")
                entry = resolved.setdefault(
                    identity,
                    {
                        "type_index_name": identity,
                        "name": str(row["name"] or row["referenced_name"] or ""),
                        "kind": str(row["kind"] or "unknown"),
                        "file_path": str(row["file_path"] or ""),
                        "start_line": int(row["start_line"] or 0),
                        "end_line": int(row["end_line"] or 0),
                        "full_definition": str(row["full_definition"] or ""),
                        "reference_kinds": [],
                        "reference_lines": [],
                    },
                )
            else:
                unresolved_key = (
                    str(row["referenced_name"] or ""),
                    str(row["resolution_reason"] or "type_not_resolved"),
                )
                entry = unresolved.setdefault(
                    unresolved_key,
                    {
                        "name": unresolved_key[0],
                        "reference_kinds": [],
                        "reference_lines": [],
                        "reason": unresolved_key[1],
                    },
                )
            if reference_kind and reference_kind not in entry["reference_kinds"]:
                entry["reference_kinds"].append(reference_kind)
            if reference_line > 0 and reference_line not in entry["reference_lines"]:
                entry["reference_lines"].append(reference_line)

        referenced_types = list(resolved.values())
        unresolved_types = list(unresolved.values())
        kind_order = {
            "return": 0,
            "parameter": 1,
            "function_pointer": 2,
            "local": 3,
            "cast": 4,
            "sizeof": 5,
            "alignof": 6,
            "offsetof": 7,
            "compound_literal": 8,
            "member_access": 9,
        }
        for entry in referenced_types + unresolved_types:
            entry["reference_kinds"] = sorted(
                entry["reference_kinds"], key=lambda value: (kind_order.get(value, 99), value)
            )
            entry["reference_lines"] = sorted(entry["reference_lines"])
        referenced_types.sort(key=lambda item: item["type_index_name"])
        unresolved_types.sort(key=lambda item: (item["name"], item["reason"]))
        result: Dict[str, Any] = {"referenced_types": referenced_types}
        if unresolved_types:
            result["unresolved_referenced_types"] = unresolved_types
        return result

    # ── Call Edges ──

    def insert_call_edge(
        self,
        caller_name: str,
        caller_file: str,
        callee_name: str,
        callee_file: str = "",
        call_line: int = 0,
        call_type: str = "direct",
        callee_kind: str = "unknown",
        callee_signature: str = "",
    ):
        self._invalidate_callgraph_query_cache()
        self._conn.execute(
            "INSERT OR IGNORE INTO call_edges "
            "(caller_name, caller_file, callee_name, callee_file, call_line, call_type, "
            "callee_kind, callee_signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                caller_name,
                caller_file,
                callee_name,
                callee_file,
                call_line,
                call_type,
                callee_kind,
                callee_signature,
            ),
        )

    def insert_call_edges_batch(self, rows: List[tuple]):
        self._invalidate_callgraph_query_cache()
        normalized_rows = []
        for row in rows:
            if len(row) == 6:
                normalized_rows.append((*row, "unknown", ""))
            elif len(row) == 7:
                normalized_rows.append((*row, ""))
            else:
                normalized_rows.append(row)
        self._conn.executemany(
            "INSERT OR IGNORE INTO call_edges "
            "(caller_name, caller_file, callee_name, callee_file, call_line, call_type, "
            "callee_kind, callee_signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            normalized_rows,
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
        return [
            {
                "name": r["caller_name"],
                "filename": r["caller_file"],
                "callee_filename": r["callee_file"],
                "lineNumber": r["call_line"],
            }
            for r in rows
        ]

    def get_all_callers(
        self,
        func_name: str,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        self._callgraph_read_semaphore.acquire()
        try:
            rows = self._conn.execute(
                "SELECT DISTINCT caller_name, caller_file, callee_file, call_line, call_type, "
                "callee_kind "
                "FROM call_edges WHERE callee_name = ? "
                "ORDER BY caller_name, caller_file, call_type, call_line",
                (func_name,),
            ).fetchall()
        finally:
            self._callgraph_read_semaphore.release()
        if callee_file:
            rows = [
                row
                for row in rows
                if self._paths_match_hint(str(row["callee_file"] or ""), callee_file)
            ]
        return [
            {
                "name": row["caller_name"],
                "filename": row["caller_file"],
                "lineNumber": row["call_line"],
                "call_type": row["call_type"],
                "callee_kind": row["callee_kind"],
            }
            for row in rows
        ]

    def get_callees(
        self,
        func_name: str,
        limit: int = 30,
        caller_file: str = "",
    ) -> List[Dict[str, Any]]:
        cache_key = (str(func_name), int(limit), str(caller_file or ""))
        with self._query_cache_lock:
            cached = self._callee_cache.get(cache_key)
            if cached is not None:
                self._callee_cache_hits += 1
                return self._clone_query_rows(cached)
            self._callee_cache_misses += 1
            cache_version = self._callgraph_cache_version

        if caller_file:
            self._callgraph_read_semaphore.acquire()
            try:
                all_rows = self._conn.execute(
                    "SELECT DISTINCT callee_name, callee_file, call_line, call_type, callee_kind, "
                    "callee_signature, "
                    "caller_file "
                    "FROM call_edges WHERE caller_name = ?",
                    (func_name,),
                ).fetchall()
            finally:
                self._callgraph_read_semaphore.release()
            rows = [
                row
                for row in all_rows
                if self._paths_match_hint(str(row["caller_file"] or ""), caller_file)
            ][:limit]
        else:
            self._callgraph_read_semaphore.acquire()
            try:
                rows = self._conn.execute(
                    "SELECT DISTINCT callee_name, callee_file, call_line, call_type, callee_kind, "
                    "callee_signature "
                    "FROM call_edges "
                    "WHERE caller_name = ? LIMIT ?",
                    (func_name, limit),
                ).fetchall()
            finally:
                self._callgraph_read_semaphore.release()
        result = [
            {
                "name": r["callee_name"],
                "filename": r["callee_file"],
                "lineNumber": r["call_line"],
                "call_type": r["call_type"],
                "callee_kind": r["callee_kind"],
                "callee_signature": r["callee_signature"],
            }
            for r in rows
        ]
        with self._query_cache_lock:
            if cache_version == self._callgraph_cache_version:
                self._callee_cache[cache_key] = self._clone_query_rows(result)
        return result

    def get_all_callees(
        self,
        func_name: str,
        caller_file: str = "",
    ) -> List[Dict[str, Any]]:
        self._callgraph_read_semaphore.acquire()
        try:
            rows = self._conn.execute(
                "SELECT DISTINCT callee_name, callee_file, call_line, call_type, callee_kind, "
                "callee_signature, "
                "caller_file "
                "FROM call_edges WHERE caller_name = ? "
                "ORDER BY callee_name, callee_file, call_type, call_line",
                (func_name,),
            ).fetchall()
        finally:
            self._callgraph_read_semaphore.release()
        if caller_file:
            rows = [
                row
                for row in rows
                if self._paths_match_hint(str(row["caller_file"] or ""), caller_file)
            ]
        return [
            {
                "name": row["callee_name"],
                "filename": row["callee_file"],
                "lineNumber": row["call_line"],
                "call_type": row["call_type"],
                "callee_kind": row["callee_kind"],
                "callee_signature": row["callee_signature"],
            }
            for row in rows
        ]

    def get_call_edge_records(
        self,
        func_name: str,
        *,
        caller_file: str = "",
    ) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT callee_name, callee_file, call_line, call_type, callee_kind, "
            "callee_signature, caller_file FROM call_edges WHERE caller_name = ? "
            "ORDER BY call_line, callee_name, callee_file",
            (func_name,),
        ).fetchall()
        if caller_file:
            rows = [
                row
                for row in rows
                if self._paths_match_hint(str(row["caller_file"] or ""), caller_file)
            ]
        return [
            {
                "name": row["callee_name"],
                "filename": row["callee_file"],
                "call_line": row["call_line"],
                "call_type": row["call_type"],
                "callee_kind": row["callee_kind"],
                "callee_signature": row["callee_signature"],
                "caller_file": row["caller_file"],
            }
            for row in rows
        ]

    @staticmethod
    def _paths_match_hint(stored_path: str, hint_path: str) -> bool:
        stored = str(stored_path or "").replace("\\", "/").strip()
        hint = str(hint_path or "").replace("\\", "/").strip()
        if not stored or not hint:
            return False
        stored = stored.lstrip("./")
        hint = hint.lstrip("./")
        return stored == hint or stored.endswith(f"/{hint}") or hint.endswith(f"/{stored}")

    def find_callers_without_callee(
        self,
        acquire_func: str,
        release_func: str,
        *,
        limit: int = 100,
        offset: int = 0,
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
            ORDER BY caller_name, caller_file
            LIMIT ? OFFSET ?
            """,
            (acquire_func, release_func, limit, max(0, int(offset))),
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
            "SELECT name, file_path, start_line FROM functions " "WHERE is_declaration = 1"
        ).fetchall()

        normalized_headers = (
            {self._normalize_source_relative_path(header, source_root) for header in header_files}
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

    def insert_indirect_call(
        self,
        caller: str,
        callee: str,
        source: str = "svf-ander",
        confidence: float = 1.0,
        call_file: str = "",
        call_line: int = 0,
        svf_group: str = "default",
        callsite_id: str = "",
        pointer_symbol: str = "",
        pointer_kind: str = "unknown",
        pointer_type: str = "",
        pointer_signature: str = "",
        callsite_expression: str = "",
        guard: str = "",
    ):
        self._invalidate_callgraph_query_cache()
        cursor = self._conn.execute(
            "INSERT OR IGNORE INTO indirect_calls "
            "(caller_name, callee_name, call_file, call_line, callsite_id, pointer_symbol, "
            "pointer_kind, pointer_type, pointer_signature, callsite_expression, call_guard, "
            "source, confidence, svf_group) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                caller,
                callee,
                call_file,
                call_line,
                callsite_id,
                pointer_symbol,
                pointer_kind,
                pointer_type,
                pointer_signature,
                callsite_expression,
                guard,
                source,
                confidence,
                svf_group,
            ),
        )
        return max(0, int(cursor.rowcount or 0))

    def get_indirect_call_records(
        self,
        func_name: str,
        *,
        caller_file: str = "",
        limit: int = 2_147_483_647,
    ) -> List[Dict[str, Any]]:
        self._callgraph_read_semaphore.acquire()
        try:
            rows = self._conn.execute(
                "SELECT callee_name, call_file, call_line, callsite_id, pointer_symbol, "
                "pointer_kind, pointer_type, pointer_signature, callsite_expression, "
                "call_guard, source, confidence, svf_group FROM indirect_calls "
                "WHERE caller_name = ? ORDER BY callee_name, call_file, call_line, "
                "callsite_id, pointer_symbol, source, svf_group LIMIT ?",
                (func_name, int(limit)),
            ).fetchall()
        finally:
            self._callgraph_read_semaphore.release()
        if caller_file:
            rows = [
                row
                for row in rows
                if self._paths_match_hint(str(row["call_file"] or ""), caller_file)
            ]
        return [
            {
                "name": row["callee_name"],
                "call_file": row["call_file"],
                "call_line": row["call_line"],
                "callsite_id": row["callsite_id"],
                "pointer_symbol": row["pointer_symbol"],
                "pointer_kind": row["pointer_kind"],
                "pointer_type": row["pointer_type"],
                "pointer_signature": row["pointer_signature"],
                "callsite_expression": row["callsite_expression"],
                "guard": row["call_guard"],
                "source": row["source"],
                "confidence": row["confidence"],
                "svf_group": row["svf_group"],
                "call_type": "indirect",
            }
            for row in rows
        ]

    def get_indirect_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        cache_key = (str(func_name), int(limit))
        with self._query_cache_lock:
            cached = self._indirect_callee_cache.get(cache_key)
            if cached is not None:
                self._indirect_callee_cache_hits += 1
                return self._clone_query_rows(cached)
            self._indirect_callee_cache_misses += 1
            cache_version = self._callgraph_cache_version

        self._callgraph_read_semaphore.acquire()
        try:
            rows = self._conn.execute(
                "SELECT callee_name, source, MAX(confidence) AS confidence, "
                "GROUP_CONCAT(DISTINCT svf_group) AS svf_groups, "
                "MAX(call_file) AS call_file, MAX(call_line) AS call_line "
                "FROM indirect_calls WHERE caller_name = ? "
                "GROUP BY caller_name, callee_name, source "
                "ORDER BY confidence DESC LIMIT ?",
                (func_name, limit),
            ).fetchall()
        finally:
            self._callgraph_read_semaphore.release()
        result = []
        for r in rows:
            groups = self._split_svf_groups(r["svf_groups"])
            result.append(
                {
                    "name": r["callee_name"],
                    "source": r["source"],
                    "confidence": r["confidence"],
                    "svf_group": groups[0] if groups else "",
                    "svf_groups": groups,
                    "call_file": r["call_file"],
                    "call_line": r["call_line"],
                }
            )
        with self._query_cache_lock:
            if cache_version == self._callgraph_cache_version:
                self._indirect_callee_cache[cache_key] = self._clone_query_rows(result)
        return result

    def get_indirect_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT caller_name, source, MAX(confidence) AS confidence, "
            "GROUP_CONCAT(DISTINCT svf_group) AS svf_groups, "
            "MAX(call_file) AS call_file, MAX(call_line) AS call_line "
            "FROM indirect_calls WHERE callee_name = ? "
            "GROUP BY caller_name, callee_name, source "
            "ORDER BY confidence DESC LIMIT ?",
            (func_name, limit),
        ).fetchall()
        return [
            {
                "name": r["caller_name"],
                "source": r["source"],
                "confidence": r["confidence"],
                "svf_groups": self._split_svf_groups(r["svf_groups"]),
                "call_file": r["call_file"],
                "call_line": r["call_line"],
            }
            for r in rows
        ]

    # ── Taint Signatures (SVF/Saber) ──

    def insert_taint_signature(
        self,
        source_func: str,
        sink_func: str,
        bug_type: str,
        file_path: str = "",
        line: int = 0,
        tool: str = "saber",
        svf_group: str = "default",
    ):
        cursor = self._conn.execute(
            "INSERT OR IGNORE INTO taint_signatures "
            "(source_func, sink_func, bug_type, file_path, line, tool, svf_group) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(source_func or ""),
                str(sink_func or ""),
                str(bug_type or ""),
                str(file_path or ""),
                int(line or 0),
                str(tool or "saber"),
                str(svf_group or "default"),
            ),
        )
        return max(0, int(cursor.rowcount or 0))

    def get_taint_bugs(self, bug_type: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        if bug_type:
            rows = self._conn.execute(
                "SELECT source_func, sink_func, bug_type, file_path, line, tool, "
                "MIN(svf_group) AS svf_group, GROUP_CONCAT(DISTINCT svf_group) AS svf_groups "
                "FROM taint_signatures WHERE bug_type LIKE ? "
                "GROUP BY source_func, sink_func, bug_type, file_path, line, tool "
                "ORDER BY file_path, line, bug_type, tool, source_func, sink_func LIMIT ?",
                (f"%{bug_type}%", limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT source_func, sink_func, bug_type, file_path, line, tool, "
                "MIN(svf_group) AS svf_group, GROUP_CONCAT(DISTINCT svf_group) AS svf_groups "
                "FROM taint_signatures "
                "GROUP BY source_func, sink_func, bug_type, file_path, line, tool "
                "ORDER BY file_path, line, bug_type, tool, source_func, sink_func LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_with_svf_groups(r) for r in rows]

    def find_function_at(self, file_path: str, line: int) -> Optional[Dict[str, Any]]:
        """通过 (file, line) 定位包含该行的函数——Clang/SVF 坐标缝合点。"""
        row = self._conn.execute(
            "SELECT * FROM functions WHERE file_path = ? "
            "AND start_line <= ? AND end_line >= ? AND is_declaration = 0 "
            "LIMIT 1",
            (file_path, line, line),
        ).fetchone()
        return dict(row) if row else None

    def get_enriched_taint_bugs(
        self,
        bug_type: str = "",
        func_name: str = "",
        limit: int = 50,
        func_names: Optional[List[str]] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """污点缺陷 JOIN 函数表，返回带 AST 上下文的富结果。"""
        where = ["1=1"]
        params: list = []
        if bug_type:
            where.append("t.bug_type LIKE ?")
            params.append(f"%{bug_type}%")
        if func_name:
            where.append("(t.source_func = ? OR t.sink_func = ? OR f.name = ?)")
            params.extend([func_name, func_name, func_name])
        normalized_func_names = sorted(
            {str(name).strip() for name in (func_names or []) if str(name).strip()}
        )
        if normalized_func_names:
            where.append(
                "EXISTS ("
                "SELECT 1 FROM json_each(?) reachable "
                "WHERE reachable.value = t.source_func "
                "OR reachable.value = t.sink_func "
                "OR reachable.value = f.name"
                ")"
            )
            params.append(
                json.dumps(
                    normalized_func_names,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
        params.extend([limit, max(0, int(offset))])
        rows = self._conn.execute(
            f"SELECT t.*, f.name AS func_name, f.signature, "
            f"f.start_line AS func_start, f.end_line AS func_end "
            f"FROM ("
            f"SELECT source_func, sink_func, bug_type, file_path, line, tool, "
            f"MIN(svf_group) AS svf_group, GROUP_CONCAT(DISTINCT svf_group) AS svf_groups "
            f"FROM taint_signatures "
            f"GROUP BY source_func, sink_func, bug_type, file_path, line, tool"
            f") t "
            f"LEFT JOIN functions f ON f.file_path = t.file_path "
            f"AND f.start_line <= t.line AND f.end_line >= t.line "
            f"AND f.is_declaration = 0 "
            f"WHERE {' AND '.join(where)} "
            f"ORDER BY t.file_path, t.line, t.bug_type, t.tool, "
            f"t.source_func, t.sink_func, f.file_path, f.start_line, "
            f"f.name, f.signature LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [self._row_with_svf_groups(r) for r in rows]

    @staticmethod
    def _split_svf_groups(raw: Any) -> List[str]:
        return sorted({part for part in str(raw or "").split(",") if part})

    @classmethod
    def _row_with_svf_groups(cls, row: Any) -> Dict[str, Any]:
        data = dict(row)
        data["svf_groups"] = cls._split_svf_groups(data.get("svf_groups"))
        if not data.get("svf_group") and data["svf_groups"]:
            data["svf_group"] = data["svf_groups"][0]
        return data

    # ── Utilities ──

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def stats(self) -> Dict[str, int]:
        result = {}
        for table in (
            "functions",
            "type_definitions",
            "call_edges",
            "macro_definitions",
            "global_variables",
            "function_symbol_refs",
            "function_macro_refs",
            "function_type_refs",
            "translation_units",
            "indirect_calls",
            "taint_signatures",
            "ir_statements",
            "ir_resource_events",
            "ir_lock_events",
            "ir_shared_accesses",
            "ir_path_slices",
            "function_contracts",
        ):
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
