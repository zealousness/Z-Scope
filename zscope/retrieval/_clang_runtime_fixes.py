"""Runtime fixes for clangd extraction and derived-index rebuilds.

This module keeps the compatibility surface of the existing retrieval modules while
installing narrowly-scoped fixes for three production issues:

* synchronous LSP requests were polled every 50 ms, limiting clangd throughput to
  roughly 20 requests/second even when clangd answered immediately;
* clangd server->client requests (notably workDoneProgress/create) were mistaken
  for responses and never acknowledged;
* derived symbol/type-reference index invalidation forced translation units to be
  re-extracted and could lose the need-to-rebuild state after an interrupted run.

The installer patches the existing classes rather than replacing public imports so
both the direct ``clang`` backend and the ``unified`` backend receive the same fix.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import clang_backend as _backend_mod
from . import clang_extractor as _extractor_mod
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)

_SYMBOL_DIRTY_KEY = "symbol_context_index_dirty"
_TYPE_REF_DIRTY_KEY = "function_type_ref_index_dirty"


def _condition(extractor: Any) -> threading.Condition:
    cond = getattr(extractor, "_response_cond", None)
    if cond is None:
        cond = threading.Condition(extractor._lock)
        extractor._response_cond = cond
    return cond


def _metadata_get(db: Any, key: str) -> str:
    getter = getattr(db, "get_metadata", None)
    if not callable(getter):
        return ""
    try:
        return str(getter(key) or "")
    except Exception:
        return ""


def _metadata_set(db: Any, key: str, value: str) -> None:
    setter = getattr(db, "set_metadata", None)
    if callable(setter):
        setter(key, value)


def install_clang_runtime_fixes() -> None:
    ClangExtractor = _extractor_mod.ClangExtractor
    ClangBackend = _backend_mod.ClangBackend

    if getattr(ClangExtractor, "_zscope_runtime_fixes_installed", False):
        return

    original_extractor_init = ClangExtractor.__init__
    original_rebuild_type_refs = ClangExtractor.rebuild_function_type_refs

    def extractor_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_extractor_init(self, *args, **kwargs)
        self._response_cond = threading.Condition(self._lock)
        self._pending_request_ids: set[int] = set()

    def send_request(
        self: Any,
        method: str,
        params: Any,
        timeout: int = 120,
    ) -> Any:
        """Send one JSON-RPC request and wait for its exact response.

        Responses wake the waiter through a Condition instead of a 50 ms polling
        sleep. ``timeout`` is a hard wall-clock timeout and is not extended by
        unrelated background-index progress notifications.
        """
        cond = _condition(self)
        if not hasattr(self, "_pending_request_ids"):
            self._pending_request_ids = set()

        with cond:
            self._id_counter += 1
            msg_id = self._id_counter
            self._pending_request_ids.add(msg_id)

        msg = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
        self._write_message(msg)

        deadline = time.monotonic() + max(0.0, float(timeout))
        response = None
        try:
            with cond:
                while msg_id not in self._responses:
                    process = self.process
                    if process is not None and process.poll() is not None:
                        logger.error(
                            "clangd exited while waiting for LSP request '%s' (id=%d, rc=%s)",
                            method,
                            msg_id,
                            process.returncode,
                        )
                        return None

                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        logger.warning("LSP request '%s' timed out (id=%d)", method, msg_id)
                        return None

                    # Normal responses call notify_all() and wake immediately. The
                    # bounded wait only ensures a dead clangd process is noticed even
                    # if stdout closes without another dispatch.
                    cond.wait(timeout=min(remaining, 0.5))

                response = self._responses.pop(msg_id)
        finally:
            with cond:
                self._pending_request_ids.discard(msg_id)
                if response is None:
                    self._responses.pop(msg_id, None)

        if "error" in response:
            logger.debug("LSP error for %s: %s", method, response["error"])
            return None
        return response.get("result")

    def dispatch_message(self: Any, msg: dict) -> None:
        """Dispatch JSON-RPC calls, notifications and replies without ID confusion."""
        method = msg.get("method")
        has_id = "id" in msg

        # clangd -> client request. A JSON-RPC request has both method and id;
        # it must never be inserted into the response map for one of our calls.
        if method is not None and has_id:
            request_id = msg.get("id")
            if method == "window/workDoneProgress/create":
                reply = {"jsonrpc": "2.0", "id": request_id, "result": None}
            else:
                logger.debug("Unhandled clangd client request: %s", method)
                reply = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            self._write_message(reply)
            return

        # clangd -> client notification.
        if method is not None:
            if method == "$/progress":
                self._last_progress_time = time.time()
            return

        # Response to a request sent by this client.
        if has_id:
            cond = _condition(self)
            pending = getattr(self, "_pending_request_ids", None)
            with cond:
                if pending is None or msg.get("id") in pending:
                    self._responses[msg.get("id")] = msg
                    cond.notify_all()
                else:
                    logger.debug("Ignoring late/unsolicited LSP reply id=%s", msg.get("id"))

    def wait_for_indexing(
        self: Any,
        timeout: int = 300,
        idle_threshold: float = 5.0,
    ) -> bool:
        """Wait for clangd index activity to become idle with a hard timeout."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() < deadline:
            elapsed = time.time() - self._last_progress_time
            if elapsed >= idle_threshold and self._initialized:
                logger.info("clangd indexing appears idle (%.1fs no progress)", elapsed)
                return True
            time.sleep(0.1)
        logger.warning("wait_for_indexing timed out after %ds", timeout)
        return False

    def collect_function_symbol_refs(
        self: Any,
        function: Dict[str, Any],
        function_file: str,
        source_path: Path,
        lines: List[str],
        globals_by_name: Dict[str, List[Dict[str, Any]]],
        macros_by_name: Dict[str, List[Dict[str, Any]]],
        aggregated: Dict[Tuple[str, str, str, str, str, int], str],
        macro_refs: set[Tuple[int, int, int]],
        include_closure: Optional[List[str]] = None,
    ) -> None:
        """Collect direct symbol references and query clangd only for ambiguity.

        The fast path is deliberately conservative: it is used only when exactly
        one indexed global/macro candidate exists for the ordinary identifier.
        Candidate rows are not visibility-filtered before resolution because a
        visible ``extern`` declaration may resolve to a definition in another TU.
        """
        del include_closure  # kept for call-site compatibility and future metrics
        start_line = max(1, int(function.get("start_line") or 1))
        end_line = min(len(lines), max(start_line, int(function.get("end_line") or start_line)))
        body_lines = lines[start_line - 1 : end_line]
        local_declarations = self._local_identifier_declaration_lines(
            "".join(body_lines),
            str(function.get("signature") or ""),
            start_line,
        )

        for offset, raw_line in enumerate(body_lines):
            absolute_line = start_line + offset
            if raw_line.lstrip().startswith("#"):
                continue
            masked_line = self._mask_c_comments_and_literals(raw_line)
            for match in re.finditer(r"\b[A-Za-z_]\w*\b", masked_line):
                name = match.group(0)
                global_candidates = list(globals_by_name.get(name, []))
                macro_candidates = list(macros_by_name.get(name, []))
                if not global_candidates and not macro_candidates:
                    continue

                local_line = local_declarations.get(name)
                is_shadowed = local_line is not None and absolute_line >= local_line
                is_field_access = self._is_field_access(masked_line, match.start())

                # A local declaration or field access can rule out the global
                # candidate before paying for an LSP round trip. Macro candidates
                # remain because preprocessing happens before C name lookup.
                if is_shadowed or is_field_access:
                    global_candidates = []
                if not global_candidates and not macro_candidates:
                    continue

                candidate_count = len(global_candidates) + len(macro_candidates)
                definitions: List[Tuple[str, int]] = []
                if candidate_count > 1:
                    self._symbol_ref_definition_requests = (
                        int(getattr(self, "_symbol_ref_definition_requests", 0)) + 1
                    )
                    definitions = self._definition_locations(
                        source_path,
                        absolute_line,
                        match.start(),
                    )
                else:
                    self._symbol_ref_fast_resolved = (
                        int(getattr(self, "_symbol_ref_fast_resolved", 0)) + 1
                    )

                if global_candidates:
                    global_record = self._resolve_symbol_candidate(
                        global_candidates,
                        function_file,
                        definitions,
                    )
                    if global_record is not None:
                        symbol_file = str(global_record.get("file_path") or "")
                        key = (
                            str(function.get("name") or ""),
                            function_file,
                            name,
                            "global",
                            symbol_file,
                            absolute_line,
                        )
                        aggregated[key] = self._merge_access_kind(
                            aggregated.get(key, "unknown"),
                            self._global_access_kind(
                                masked_line,
                                match.start(),
                                match.end(),
                            ),
                        )

                if macro_candidates:
                    macro_record = self._resolve_symbol_candidate(
                        macro_candidates,
                        function_file,
                        definitions,
                    )
                    if macro_record is None:
                        continue
                    if bool(macro_record.get("is_function_like")) and not re.match(
                        r"\s*\(", masked_line[match.end() :]
                    ):
                        continue
                    function_id = int(function.get("id") or 0)
                    macro_id = int(macro_record.get("id") or 0)
                    if function_id > 0 and macro_id > 0:
                        macro_refs.add((function_id, macro_id, absolute_line))

    def rebuild_function_symbol_refs(self: Any, db: KnowledgeDB) -> int:
        get_functions = getattr(db, "get_function_records", None)
        get_globals = getattr(db, "get_global_variables", None)
        get_macros = getattr(db, "get_all_macro_definitions", None)
        clear_refs = getattr(db, "clear_function_symbol_refs", None)
        insert_refs = getattr(db, "insert_function_symbol_refs_batch", None)
        replace_macro_refs = getattr(db, "replace_function_macro_refs", None)
        if not all(
            callable(method)
            for method in (
                get_functions,
                get_globals,
                get_macros,
                clear_refs,
                insert_refs,
                replace_macro_refs,
            )
        ):
            return 0

        functions = [row for row in get_functions() if not row.get("is_declaration")]
        globals_by_name = self._records_by_name(get_globals())
        macros_by_name = self._records_by_name(get_macros())
        aggregated: Dict[Tuple[str, str, str, str, str, int], str] = {}
        macro_refs: set[Tuple[int, int, int]] = set()
        self._symbol_ref_definition_requests = 0
        self._symbol_ref_fast_resolved = 0

        functions_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for function in functions:
            functions_by_file.setdefault(str(function.get("file_path") or ""), []).append(function)

        include_closure_getter = getattr(db, "get_transitive_include_closure", None)
        for function_file, file_functions in sorted(functions_by_file.items()):
            source_path = self._resolve_indexed_source_path(function_file)
            lines = self._read_source_lines(source_path)
            if not lines:
                continue
            include_closure = (
                list(include_closure_getter(function_file))
                if callable(include_closure_getter)
                else [function_file]
            )
            document_opened = False
            try:
                document_opened = bool(self.open_document(source_path))
            except Exception:
                document_opened = False

            try:
                for function in file_functions:
                    self._collect_function_symbol_refs(
                        function,
                        function_file,
                        source_path,
                        lines,
                        globals_by_name,
                        macros_by_name,
                        aggregated,
                        macro_refs,
                        include_closure=include_closure,
                    )
            finally:
                if document_opened:
                    try:
                        self.close_document(source_path)
                    except Exception:
                        pass

        rows = [(*key, access) for key, access in sorted(aggregated.items())]
        clear_refs()
        insert_refs(rows)
        replace_macro_refs(sorted(macro_refs))
        db.commit()
        logger.info(
            "Rebuilt function symbol refs with %d clangd definition requests; "
            "%d occurrences resolved locally",
            self._symbol_ref_definition_requests,
            self._symbol_ref_fast_resolved,
        )
        return len(rows) + len(macro_refs)

    def collect_function_type_refs(
        self: Any,
        function: Dict[str, Any],
        function_file: str,
        source_path: Path,
        lines: List[str],
        types_by_name: Dict[str, List[Dict[str, Any]]],
        include_closure: List[str],
    ) -> List[Tuple[Any, ...]]:
        """Collect type refs and avoid definition RPCs for globally unique types."""
        function_id = int(function.get("id") or 0)
        if function_id <= 0:
            return []
        candidates = self._direct_function_type_candidates(function, lines, set(types_by_name))
        resolved_cache: Dict[Tuple[str, int, int], Tuple[Optional[Dict[str, Any]], str]] = {}
        rows: List[Tuple[Any, ...]] = []
        for candidate in candidates:
            name = str(candidate["name"])
            lookup_line = int(candidate.get("lookup_line") or candidate["line"])
            lookup_char = int(candidate.get("lookup_char") or candidate["character"])
            cache_key = (name, lookup_line, lookup_char)
            if cache_key not in resolved_cache:
                records = list(types_by_name.get(name, []))
                unique_records = {int(item.get("id") or 0): item for item in records}
                unique_records.pop(0, None)
                if len(unique_records) == 1:
                    resolved_cache[cache_key] = (next(iter(unique_records.values())), "")
                    self._type_ref_fast_resolved = (
                        int(getattr(self, "_type_ref_fast_resolved", 0)) + 1
                    )
                else:
                    self._type_ref_definition_requests = (
                        int(getattr(self, "_type_ref_definition_requests", 0)) + 1
                    )
                    definitions = self._definition_locations(source_path, lookup_line, lookup_char)
                    resolved_cache[cache_key] = self._resolve_type_definition_candidate(
                        name,
                        records,
                        definitions,
                        function_file,
                        include_closure,
                    )

            type_record, reason = resolved_cache[cache_key]
            if type_record is None:
                logger.warning(
                    "[type-context] unresolved function=%s file=%s type=%s line=%d reason=%s",
                    function.get("name"),
                    function_file,
                    name,
                    int(candidate["line"]),
                    reason,
                )
                rows.append(
                    (
                        function_id,
                        None,
                        "",
                        name,
                        function_file,
                        int(candidate["line"]),
                        str(candidate["kind"]),
                        reason,
                    )
                )
                continue
            type_index_name = KnowledgeDB.type_index_name(type_record)
            rows.append(
                (
                    function_id,
                    int(type_record["id"]),
                    type_index_name,
                    name,
                    function_file,
                    int(candidate["line"]),
                    str(candidate["kind"]),
                    "",
                )
            )
        return rows

    def rebuild_function_type_refs(self: Any, db: KnowledgeDB) -> int:
        self._type_ref_definition_requests = 0
        self._type_ref_fast_resolved = 0
        count = original_rebuild_type_refs(self, db)
        logger.info(
            "Rebuilt function type refs with %d clangd definition requests; "
            "%d lookups resolved locally",
            self._type_ref_definition_requests,
            self._type_ref_fast_resolved,
        )
        return count

    # ----- Derived-index durability / resume ---------------------------------

    def symbol_context_needs_refresh(self: Any, db: Any) -> bool:
        if _metadata_get(db, _SYMBOL_DIRTY_KEY) == "1":
            return True
        return (
            _metadata_get(db, "symbol_context_extractor_version")
            != str(self.SYMBOL_CONTEXT_EXTRACTOR_VERSION)
        )

    def mark_symbol_context_current(self: Any, db: Any) -> None:
        _metadata_set(db, "symbol_context_extractor_version", self.SYMBOL_CONTEXT_EXTRACTOR_VERSION)
        _metadata_set(db, _SYMBOL_DIRTY_KEY, "0")

    def function_type_ref_needs_refresh(self: Any, db: Any) -> bool:
        if _metadata_get(db, _TYPE_REF_DIRTY_KEY) == "1":
            return True
        return (
            _metadata_get(db, "function_type_ref_extractor_version")
            != str(self.FUNCTION_TYPE_REF_EXTRACTOR_VERSION)
        )

    def mark_function_type_ref_current(self: Any, db: Any) -> None:
        _metadata_set(
            db,
            "function_type_ref_extractor_version",
            self.FUNCTION_TYPE_REF_EXTRACTOR_VERSION,
        )
        _metadata_set(db, _TYPE_REF_DIRTY_KEY, "0")

    def run_full_extraction(self: Any) -> bool:
        """Run TU extraction while treating derived indexes as independently resumable."""
        try:
            file_list = self._collect_source_files()
            changed_count = 0
            prescanned_tus: Dict[str, Tuple[int, bool]] = {}
            if self._db is None:
                self._status = "error"
                return False

            db = self._db
            source_root = self._source_path
            force_macro_refresh = self._macro_index_needs_refresh(db)
            force_symbol_context_refresh = self._symbol_context_index_needs_refresh(db)
            force_type_refresh = self._type_index_needs_refresh(db)
            force_function_type_ref_refresh = self._function_type_ref_index_needs_refresh(db)
            if force_macro_refresh:
                clear_macros = getattr(db, "clear_macro_definitions", None)
                if callable(clear_macros):
                    clear_macros()

            def normalize_db_path(path_value: str) -> str:
                path = Path(str(path_value))
                if not path.is_absolute() and source_root is not None:
                    path = source_root / path
                return str(path.resolve())

            current_files: Dict[str, Path] = {
                normalize_db_path(str(fp)): fp.resolve() for fp in file_list
            }
            deleted_tus = [
                tu
                for tu in db.get_all_tus()
                if normalize_db_path(str(tu.get("file_path") or "")) not in current_files
            ]
            if deleted_tus:
                _metadata_set(db, _SYMBOL_DIRTY_KEY, "1")
                _metadata_set(db, _TYPE_REF_DIRTY_KEY, "1")
                force_symbol_context_refresh = True
                force_function_type_ref_refresh = True

            force_refresh_paths: set[str] = set()
            deleted_paths: List[Path] = []
            for tu in deleted_tus:
                tu_id = int(tu["id"])
                impact = db.get_tu_delete_impact(tu_id)
                db.delete_tu(tu_id)
                raw_path = str(tu.get("file_path") or "")
                if raw_path:
                    deleted_paths.append(Path(normalize_db_path(raw_path)))
                for related in impact.get("related_files", []):
                    related_key = normalize_db_path(str(related))
                    related_path = current_files.get(related_key)
                    if related_path is not None and self._is_path_allowed(related_path):
                        force_refresh_paths.add(related_key)

            if not file_list:
                logger.warning("No source files found in %s", self._source_path)
                self._mark_macro_index_current(db)
                self._mark_symbol_context_index_current(db)
                self._mark_type_index_current(db)
                self._mark_function_type_ref_index_current(db)
                self._status = "ready"
                return True

            from .clang_extractor import ClangExtractor

            for fp in file_list:
                fp = fp.resolve()
                file_hash = ClangExtractor._compute_file_hash(fp)
                tu_id, changed = db.register_tu_hash(str(fp), file_hash)
                # Only base-fact invalidation may force a TU re-extraction.
                # Symbol/type-ref versions are derived indexes and must not turn
                # every unchanged TU into pending work.
                if not changed and (
                    normalize_db_path(str(fp)) in force_refresh_paths
                    or force_macro_refresh
                    or force_type_refresh
                ):
                    changed = True
                    db.mark_tu_pending(tu_id)
                prescanned_tus[str(fp)] = (tu_id, changed)
                if changed:
                    changed_count += 1

            # If base facts changed, mark derived indexes dirty before extraction.
            # A crash at any later point therefore causes the next process to resume
            # the derived rebuild instead of silently accepting stale refs.
            if changed_count > 0:
                _metadata_set(db, _SYMBOL_DIRTY_KEY, "1")
                _metadata_set(db, _TYPE_REF_DIRTY_KEY, "1")
                force_symbol_context_refresh = True
                force_function_type_ref_refresh = True

            if changed_count == 0:
                logger.info(
                    "Incremental: all %d TU facts unchanged, reusing cached KnowledgeDB",
                    len(file_list),
                )
                if force_symbol_context_refresh or force_function_type_ref_refresh:
                    if not self._ensure_extractor():
                        self._status = "error"
                        return False
                    extractor = self._extractor
                    if extractor is None:
                        self._status = "error"
                        return False
                    if deleted_paths and hasattr(extractor, "notify_files_deleted"):
                        extractor.notify_files_deleted(deleted_paths)
                    extractor.wait_for_indexing(timeout=120, idle_threshold=3.0)

                    if force_symbol_context_refresh:
                        ref_count = extractor.rebuild_function_symbol_refs(db)
                        logger.info("Resumed derived rebuild: %d function symbol references", ref_count)
                        self._mark_symbol_context_index_current(db)
                    if force_function_type_ref_refresh:
                        type_ref_count = extractor.rebuild_function_type_refs(db)
                        logger.info(
                            "Resumed derived rebuild: %d direct function type references",
                            type_ref_count,
                        )
                        self._mark_function_type_ref_index_current(db)

                self._mark_macro_index_current(db)
                self._mark_type_index_current(db)
                self._status = "ready"
                return True

            logger.info(
                "Incremental: %d/%d files changed, starting clangd extraction",
                changed_count,
                len(file_list),
            )

            if not self._ensure_extractor():
                self._status = "error"
                return False
            extractor = self._extractor
            if extractor is None:
                self._status = "error"
                return False
            if deleted_paths and hasattr(extractor, "notify_files_deleted"):
                extractor.notify_files_deleted(deleted_paths)

            extractor.wait_for_indexing(timeout=120, idle_threshold=3.0)
            stats = extractor.run_batch_extraction(
                file_list,
                db,
                batch_size=self._batch_size,
                prescanned_tus=prescanned_tus,
            )
            logger.info(
                "Extraction complete: %d extracted, %d skipped, %d failed",
                stats["success"],
                stats["skipped"],
                stats["failed"],
            )
            self._mark_type_index_current(db)
            if int(stats.get("failed") or 0) == 0:
                self._mark_macro_index_current(db)
                self._mark_symbol_context_index_current(db)
                self._mark_function_type_ref_index_current(db)
            else:
                logger.warning(
                    "[macro-context] extractor versions not advanced failed_tus=%d",
                    int(stats.get("failed") or 0),
                )
                logger.warning(
                    "[type-context] extractor version not advanced failed_tus=%d",
                    int(stats.get("failed") or 0),
                )
            self._status = "ready"
            return True
        except Exception as exc:
            logger.error("Extraction failed: %s", exc)
            self._status = "error"
            return False

    # Install extractor fixes.
    ClangExtractor.__init__ = extractor_init
    ClangExtractor.send_request = send_request
    ClangExtractor._dispatch_message = dispatch_message
    ClangExtractor.wait_for_indexing = wait_for_indexing
    ClangExtractor._collect_function_symbol_refs = collect_function_symbol_refs
    ClangExtractor.rebuild_function_symbol_refs = rebuild_function_symbol_refs
    ClangExtractor._collect_function_type_refs = collect_function_type_refs
    ClangExtractor.rebuild_function_type_refs = rebuild_function_type_refs
    ClangExtractor._zscope_runtime_fixes_installed = True

    # Install backend durability/invalidation fixes. Bump derived-index versions
    # because the resolver semantics and interruption guarantees changed.
    ClangBackend.SYMBOL_CONTEXT_EXTRACTOR_VERSION = "3"
    ClangBackend.FUNCTION_TYPE_REF_EXTRACTOR_VERSION = "3"
    ClangBackend._symbol_context_index_needs_refresh = symbol_context_needs_refresh
    ClangBackend._mark_symbol_context_index_current = mark_symbol_context_current
    ClangBackend._function_type_ref_index_needs_refresh = function_type_ref_needs_refresh
    ClangBackend._mark_function_type_ref_index_current = mark_function_type_ref_current
    ClangBackend._run_full_extraction = run_full_extraction


__all__ = ["install_clang_runtime_fixes"]
